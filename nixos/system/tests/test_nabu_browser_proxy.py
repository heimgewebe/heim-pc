"""Negative and positive proof of the Chrome SOCKS5 public-egress boundary."""
from __future__ import annotations

import asyncio
import importlib.util
import ipaddress
from pathlib import Path
import socket
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "nabu" / "browser_proxy.py"
SPEC = importlib.util.spec_from_file_location("nabu_browser_proxy", SOURCE)
assert SPEC and SPEC.loader
proxy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(proxy)


async def connect_socks(server_port: int, host: str, target_port: int, atyp: int = 3):
    reader, writer = await asyncio.open_connection("127.0.0.1", server_port)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    assert await reader.readexactly(2) == b"\x05\x00"
    if atyp == 1:
        address = socket.inet_pton(socket.AF_INET, host)
    elif atyp == 4:
        address = socket.inet_pton(socket.AF_INET6, host)
    else:
        name = host.encode("ascii")
        address = bytes([len(name)]) + name
    writer.write(b"\x05\x01\x00" + bytes([atyp]) + address +
                 target_port.to_bytes(2, "big"))
    await writer.drain()
    reply = await asyncio.wait_for(reader.readexactly(10), timeout=5)
    return reader, writer, reply


class BrowserProxyTests(unittest.TestCase):
    def test_global_addresses_only_including_ipv4_mapped_ipv6(self):
        for address in ("127.0.0.1", "127.1", "10.1.2.3", "192.168.4.5",
                        "169.254.169.254", "::1", "::ffff:127.0.0.1",
                        "fc00::3", "fe80::1", "0.0.0.0"):
            with self.subTest(address=address):
                self.assertFalse(proxy.public_address(address))
        for address in ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"):
            self.assertTrue(proxy.public_address(address))

    def test_refuses_mixed_dns_and_non_public_answers(self):
        pub = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
               ("8.8.8.8", 443))
        private = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
                   ("10.0.0.2", 443))
        self.assertEqual([pub], proxy.validate_resolution([pub]))
        for answers in ([], [private], [pub, private]):
            with self.subTest(answers=answers), self.assertRaises(proxy.DestinationDenied):
                proxy.validate_resolution(answers)

    def test_chrome_flags_proxy_all_urls_without_loopback_bypass(self):
        base = ["/some/chrome", "--headless=new", "--no-first-run"]
        result = proxy.guarded_chrome_command(["--", *base], 13821)
        self.assertEqual(base, result[:len(base)])
        self.assertIn("--proxy-server=socks5://127.0.0.1:13821", result)
        self.assertIn("--proxy-bypass-list=<-loopback>", result)
        self.assertIn("--disable-quic", result)
        self.assertIn("--force-webrtc-ip-handling-policy=disable_non_proxied_udp", result)
        with self.assertRaises(ValueError):
            proxy.guarded_chrome_command([*base, "--proxy-server=direct://"], 13821)

    def test_rejects_private_socks_destinations_before_connect(self):
        async def scenario():
            accepted = 0

            async def destination(reader, writer):
                nonlocal accepted
                accepted += 1
                writer.close()
                await writer.wait_closed()

            local = await asyncio.start_server(destination, "127.0.0.1", 0)
            target_port = local.sockets[0].getsockname()[1]
            server = await asyncio.start_server(proxy.handle_socks, "127.0.0.1", 0)
            try:
                port = server.sockets[0].getsockname()[1]
                cases = [
                    ("127.0.0.1", 1), ("127.1", 3),
                    ("2130706433", 3), ("localhost", 3),
                    ("192.168.1.2", 1), ("::1", 4),
                    ("::ffff:127.0.0.1", 4),
                ]
                for host, atyp in cases:
                    with self.subTest(host=host):
                        _, writer, reply = await connect_socks(port, host, target_port, atyp)
                        self.assertEqual(2, reply[1])
                        writer.close()
                        await writer.wait_closed()
                self.assertEqual(0, accepted, "private endpoint received a connection")
            finally:
                server.close()
                local.close()
                await server.wait_closed()
                await local.wait_closed()
        asyncio.run(scenario())

    def test_public_tunnel_copies_bytes_and_pins_resolved_addresses(self):
        async def scenario():
            addresses = [(socket.AF_INET, socket.SOCK_STREAM,
                          socket.IPPROTO_TCP, "", ("8.8.8.8", 443))]
            seen = []

            async def echo(reader, writer):
                data = await reader.readexactly(4)
                writer.write(data.upper())
                await writer.drain()
                writer.close()
                await writer.wait_closed()

            upstream = await asyncio.start_server(echo, "127.0.0.1", 0)
            async def resolve(host, port):
                seen.append((host, port))
                return proxy.validate_resolution(addresses)

            async def dial(given):
                self.assertEqual(addresses, given)
                return await asyncio.open_connection(
                    "127.0.0.1", upstream.sockets[0].getsockname()[1]
                )

            with patch.object(proxy, "resolve_public", resolve), patch.object(proxy, "dial_public", dial):
                server = await asyncio.start_server(proxy.handle_socks, "127.0.0.1", 0)
                try:
                    port = server.sockets[0].getsockname()[1]
                    reader, writer, reply = await connect_socks(port, "example.org", 443)
                    self.assertEqual(0, reply[1])
                    writer.write(b"test")
                    await writer.drain()
                    self.assertEqual(b"TEST", await asyncio.wait_for(reader.readexactly(4), 5))
                    self.assertEqual([("example.org", 443)], seen)
                    writer.close()
                    await writer.wait_closed()
                finally:
                    server.close()
                    upstream.close()
                    await server.wait_closed()
                    await upstream.wait_closed()
        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()