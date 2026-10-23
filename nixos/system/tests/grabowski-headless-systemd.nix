{ pkgs }:
let
  operator = import ../modules/grabowski-operator-package.nix { inherit pkgs; };
  broker = import ../modules/grabowski-broker-package.nix {
    inherit pkgs;
    lib = pkgs.lib;
    packageOnly = true;
  };
  revision = "dd6dc690285b-srcset5c51dbd24485-lock264e747ad05a-contract2681d2593edc";

  verifyIdentity = pkgs.writeText "grabowski-verify-systemd-identity.py" ''
    import grp
    import os
    from pathlib import Path
    import subprocess
    import sys

    sys.path.insert(0, "${broker}/lib/grabowski")
    import grabowski_nixos_unit_authority as authority

    def systemctl_property(prop):
        return subprocess.check_output(
            ["${pkgs.systemd}/bin/systemctl", "show", "grabowski-operator.service",
             "--property=" + prop, "--value", "--no-pager"],
            text=True, timeout=10,
        ).strip()

    pid = int(systemctl_property("MainPID"))
    if pid <= 1 or systemctl_property("ActiveState") != "active":
        raise SystemExit("operator is not an active systemd MainPID")
    expected = [
        "${operator}/bin/grabowski-operator", "-m", "grabowski_operator",
        "--transport", "streamable-http", "--host", "127.0.0.1", "--port", "18181",
    ]
    observed = [
        part.decode("utf-8", "strict")
        for part in (Path("/proc") / str(pid) / "cmdline").read_bytes().rstrip(b"\0").split(b"\0")
    ]
    if observed != expected:
        raise SystemExit("NixOS systemd MainPID /proc command identity mismatch")
    gid = grp.getgrnam("grabowski").gr_gid
    groups = (Path("/proc") / str(pid) / "status").read_text().splitlines()
    group_rows = [row for row in groups if row.startswith("Groups:")]
    if len(group_rows) != 1 or str(gid) not in group_rows[0].split()[1:]:
        raise SystemExit("operator system service did not receive restricted socket group")
    fragment = Path(systemctl_property("FragmentPath"))
    if not authority.fragment_trusted(fragment):
        print("systemd FragmentPath=", fragment, "resolved=", fragment.resolve(strict=False))
        paths = [Path("/nix"), Path("/nix/store"), Path("/etc"),
                 Path("/etc/systemd"), Path("/etc/systemd/system"),
                 fragment, fragment.resolve(strict=False)]
        for candidate in paths:
            try:
                linked = candidate.lstat()
                resolved = candidate.stat()
                print("trust-path", candidate,
                      "lmode", oct(linked.st_mode), "luid", linked.st_uid,
                      "mode", oct(resolved.st_mode), "uid", resolved.st_uid,
                      "symlink", candidate.is_symlink())
            except OSError as exc:
                print("trust-path-unavailable", candidate, type(exc).__name__, str(exc))
        raise SystemExit("NixOS root broker did not accept systemd's immutable FragmentPath")
    authorized_args = authority.expected_operator_argv(
        environ={"GRABOWSKI_NIXOS_OPERATOR_ENTRYPOINT": "${operator}/bin/grabowski-operator"},
    )
    if tuple(expected) != authorized_args:
        raise SystemExit("root broker expected command line does not match MainPID")
    print("verified systemd MainPID, exact argv, restricted socket group and root-controlled unit")
  '';

  verifyMcp = pkgs.writeText "grabowski-verify-service-mcp.py" ''
    import asyncio
    import json
    from pathlib import Path

    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    expected = set(json.loads(
        Path("${operator}/share/grabowski/config/runtime-entrypoint.json").read_text()
    )["expected_tools"])
    assert len(expected) == 203

    async def main():
        async with streamablehttp_client(
            "http://127.0.0.1:18181/mcp", timeout=10,
        ) as (read, write, *_):
            async with ClientSession(read, write) as session:
                await asyncio.wait_for(session.initialize(), timeout=25)
                listing = await asyncio.wait_for(session.list_tools(), timeout=25)
                observed = {entry.name for entry in listing.tools}
                if observed != expected:
                    raise SystemExit(
                        "headless VM MCP surface changed: missing="
                        + str(sorted(expected - observed))
                        + " unexpected=" + str(sorted(observed - expected))
                    )
                print("verified all 203 MCP tools in systemd-run NixOS")
    asyncio.run(main())
  '';

  rootBrokerNegative = pkgs.writeText "grabowski-broker-no-policy.py" ''
    import json
    import socket

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(18)
        client.connect("/run/grabowski/privileged-broker.sock")
        client.sendall(b"{}")
        client.shutdown(socket.SHUT_WR)
        payload = client.recv(4096)
    parsed = json.loads(payload)
    if not isinstance(parsed, dict) or not isinstance(parsed.get("error"), str):
        raise SystemExit("root broker accepted invalid privileged reference")
    print("verified real systemd per-request broker rejects invalid request")
  '';

  nonmemberNegative = pkgs.writeText "grabowski-broker-deny-nonmember.py" ''
    import socket
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(4)
        try:
            client.connect("/run/grabowski/privileged-broker.sock")
        except PermissionError:
            print("verified alex session cannot connect to root broker socket")
        else:
            raise SystemExit("ordinary alex process bypassed systemd-only group grant")
  '';
in
pkgs.testers.runNixOSTest {
  name = "heim-pc-grabowski-headless-systemd";
  globalTimeout = 2400;

  nodes.machine = { pkgs, ... }: {
    imports = [
      ../modules/grabowski-production.nix
      ../modules/grabowski-broker-package.nix
    ];
    networking.hostName = "grabowski-systemd-test";
    system.stateVersion = "26.05";
    users.groups.alex = { };
    users.users.alex = {
      isNormalUser = true;
      uid = 1000;
      group = "alex";
      home = "/home/alex";
      createHome = true;
    };
    services.getty.autologinUser = null;
    heimPc.grabowskiProduction = {
      enable = true;
      operatorPackage = operator;
      brokerPackage = broker;
      releaseId = revision;
    };
    virtualisation.memorySize = 4096;
    virtualisation.cores = 2;
    documentation.enable = false;
    environment.systemPackages = [ pkgs.coreutils pkgs.shadow pkgs.gnugrep ];
  };

  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target", timeout=240)
    machine.wait_until_succeeds(
        "systemctl is-active grabowski-privileged-broker.socket", timeout=160,
    )
    machine.wait_until_succeeds(
        "systemctl is-active grabowski-operator.service", timeout=160,
    )
    with subtest("systemd root-controlled unit and exact operator MainPID"):
        machine.succeed("${pkgs.python3}/bin/python3 ${verifyIdentity}")
        machine.succeed("test $(stat -c %a /run/grabowski) = 750")
        machine.succeed("test $(stat -c %a /run/grabowski/privileged-broker.sock) = 660")
        machine.succeed("test $(stat -c %U /run/grabowski/privileged-broker.sock) = root")
        machine.succeed("test $(stat -c %G /run/grabowski/privileged-broker.sock) = grabowski")
        machine.fail("id -nG alex | grep -qw grabowski")
    with subtest("real headless MCP initialize/list_tools"):
        machine.wait_until_succeeds(
            "PYTHONPATH=${operator}/lib/python3.12/site-packages "
            "${pkgs.python312}/bin/python3 -B ${verifyMcp}",
            timeout=160,
        )
    with subtest("canonical per-request root broker is fail-closed"):
        machine.succeed("${pkgs.python3}/bin/python3 ${rootBrokerNegative}")
        machine.succeed(
            "su -s ${pkgs.bash}/bin/bash -c "
            "'${pkgs.python3}/bin/python3 ${nonmemberNegative}' alex"
        )
        machine.fail("test -e /etc/grabowski/privileged-actions.json")
  '';
}