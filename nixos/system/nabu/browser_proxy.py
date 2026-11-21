"""Launch Nabu's existing Chrome behind a public-address-only SOCKS5 proxy.

The proxy lives in this process on an ephemeral localhost port. Chrome HTTP(S)
URL loads must use it even for loopback; DNS is resolved and pinned here rather
than trusted to an unchecked Chromium navigation event.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import sys


SOCKS = 5
TIMEOUT = 12
MAX_CONNECTION_SECONDS = 600
SOCKS_REPLY = b"\x05{code}\x00\x01\x00\x00\x00\x00\x00\x00"


class DestinationDenied(ValueError):
    pass


def public_address(value: str) -> bool:
    """Include IPv4-mapped IPv6 checks, not merely the outer v6 classification."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped.is_global
    return address.is_global


def validate_resolution(answers: list[tuple]) -> list[tuple]:
    """Deny mixed public/private DNS answers; use only these exact socket addrs."""
    if not answers or any(
        len(answer) < 5 or not public_address(answer[4][0])
        for answer in answers
    ):
        raise DestinationDenied("non-public resolved endpoint")
    return answers


async def resolve_public(host: str, port: int) -> list[tuple]:
    if not host or not 1 <= port <= 65535:
        raise DestinationDenied("invalid SOCKS destination")
    loop = asyncio.get_running_loop()
    try:
        answers = await asyncio.wait_for(
            loop.getaddrinfo(host, port, family=socket.AF_UNSPEC,
                             type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP),
            timeout=TIMEOUT,
        )
    except (OSError, asyncio.TimeoutError) as exc:
        raise DestinationDenied("destination unavailable") from exc
    return validate_resolution(answers)


async def dial_public(answers: list[tuple]):
    loop = asyncio.get_running_loop()
    for family, socktype, proto, _, sockaddr in answers:
        candidate = socket.socket(family, socktype, proto)
        candidate.setblocking(False)
        try:
            # Never re-resolve between the DNS check and TCP connect.
            await asyncio.wait_for(loop.sock_connect(candidate, sockaddr), timeout=TIMEOUT)
            return await asyncio.open_connection(sock=candidate)
        except (OSError, asyncio.TimeoutError):
            candidate.close()
    raise ConnectionError("public destination connection failed")


async def stream_copy(source: asyncio.StreamReader, destination: asyncio.StreamWriter):
    while chunk := await source.read(65536):
        destination.write(chunk)
        await destination.drain()
    if destination.can_write_eof():
        destination.write_eof()


async def handle_socks(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    upstream = None
    replied = False
    try:
        greeting = await asyncio.wait_for(reader.readexactly(2), timeout=TIMEOUT)
        version, count = greeting
        if version != SOCKS or not 1 <= count <= 16:
            return
        methods = await reader.readexactly(count)
        if 0 not in methods:
            writer.write(b"\x05\xff")
            await writer.drain()
            return
        writer.write(b"\x05\x00")
        await writer.drain()
        version, command, reserved, atyp = await reader.readexactly(4)
        if version != SOCKS or reserved != 0 or command != 1:
            writer.write(SOCKS_REPLY.replace(b"{code}", b"\x07"))
            await writer.drain()
            return
        if atyp == 1:
            host = socket.inet_ntop(socket.AF_INET, await reader.readexactly(4))
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
        elif atyp == 3:
            length = (await reader.readexactly(1))[0]
            if not 1 <= length <= 253:
                raise DestinationDenied("invalid domain length")
            host = (await reader.readexactly(length)).decode("idna")
        else:
            raise DestinationDenied("unsupported address type")
        port = int.from_bytes(await reader.readexactly(2), "big")
        addresses = await resolve_public(host, port)
        upstream = await dial_public(addresses)
        remote_reader, remote_writer = upstream
        writer.write(SOCKS_REPLY.replace(b"{code}", b"\x00"))
        await writer.drain()
        replied = True
        await asyncio.wait_for(
            asyncio.gather(stream_copy(reader, remote_writer),
                           stream_copy(remote_reader, writer)),
            timeout=MAX_CONNECTION_SECONDS,
        )
    except (DestinationDenied, ValueError, OSError, ConnectionError,
            asyncio.TimeoutError, asyncio.IncompleteReadError):
        if not replied and not writer.is_closing():
            writer.write(SOCKS_REPLY.replace(b"{code}", b"\x02"))
            try:
                await writer.drain()
            except (OSError, ConnectionError):
                pass
    finally:
        if upstream is not None:
            upstream[1].close()
            try:
                await upstream[1].wait_closed()
            except (OSError, ConnectionError):
                pass
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ConnectionError):
            pass


def guarded_chrome_command(args: list[str], port: int) -> list[str]:
    if args[:1] == ["--"]:
        args = args[1:]
    if not args or not args[0].startswith("/"):
        raise ValueError("pass the absolute existing Chrome argv after --")
    forbidden = ("--proxy-server", "--proxy-pac-url", "--proxy-bypass-list",
                 "--no-proxy-server", "--host-resolver-rules")
    if any(arg.startswith(forbidden) for arg in args[1:]):
        raise ValueError("conflicting Chrome network flags")
    if not 1 <= port <= 65535:
        raise ValueError("invalid ephemeral proxy port")
    return [
        *args,
        f"--proxy-server=socks5://127.0.0.1:{port}",
        "--proxy-bypass-list=<-loopback>",
        "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
        "--disable-quic",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--disable-extensions",
    ]


async def run_browser(args: list[str]) -> int:
    server = await asyncio.start_server(handle_socks, host="127.0.0.1", port=0)
    try:
        port = server.sockets[0].getsockname()[1]
        command = guarded_chrome_command(args, port)
        async with server:
            chrome = await asyncio.create_subprocess_exec(*command)
            return await chrome.wait()
    finally:
        server.close()
        await server.wait_closed()


def main() -> int:
    if len(sys.argv) < 3 or sys.argv[1] != "--":
        raise SystemExit("usage: browser_proxy.py -- /absolute/path/to/google-chrome [flags ...]")
    return asyncio.run(run_browser(sys.argv[1:]))


if __name__ == "__main__":
    raise SystemExit(main())
