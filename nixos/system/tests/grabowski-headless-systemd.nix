{ pkgs }:
let
  operator = import ../modules/grabowski-operator-package.nix { inherit pkgs; };
  broker = import ../modules/grabowski-broker-package.nix {
    inherit pkgs;
    lib = pkgs.lib;
    packageOnly = true;
  };
  revision = "dd6dc690285b-srcset5c51dbd24485-lock264e747ad05a-contract2681d2593edc";

  # Isolated VM only: one harmless fixed command, never a production allowlist.
  benignResponse = builtins.toJSON {
    schema_version = 1;
    kind = "grabowski.critical_user_data_inventory_status.v1";
    status = "running";
    scanner_sha256 = null;
    contract_sha256 = null;
    unit = "vm-only-unchanged-host";
    unit_state = {
      load = "loaded";
      active = "active";
      sub = "running";
      result = "success";
    };
    result_sha256 = null;
  };
  benignResponseFile = pkgs.writeText "vm-only-rootbroker-readback.json" benignResponse;
  syntheticPolicy = pkgs.writeText "vm-only-rootbroker-policy-NOT-PRODUCTION.json" (builtins.toJSON {
    schema_version = 2;
    actions.critical_user_data_inventory_read = {
      enabled = true;
      target_pattern = ".*";
      argv = [ "${pkgs.coreutils}/bin/cat" "${benignResponseFile}" ];
      timeout_seconds = 5;
      allowed_peer_uid = 1000;
      allowed_peer_unit = "grabowski-operator.service";
    };
  });


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
                # Use the unchanged original operator MainPID and the only
                # allowlisted VM command: immutable coreutils cat.
                answer = await asyncio.wait_for(session.call_tool(
                    "grabowski_critical_user_data_inventory_read",
                    {"operation": "status", "scanner_sha256": "a" * 64,
                     "contract_sha256": "b" * 64},
                ), timeout=50)
                if getattr(answer, "isError", False):
                    raise SystemExit("positive original MCP broker call returned an error")
                candidates = [getattr(answer, "structuredContent", None)]
                for item in answer.content:
                    try:
                        candidates.append(json.loads(item.text))
                    except (AttributeError, ValueError, TypeError):
                        pass
                valid = False
                for candidate in candidates:
                    if (isinstance(candidate, dict) and "success" not in candidate
                        and isinstance(candidate.get("result"), dict)):
                        candidate = candidate["result"]
                    if (isinstance(candidate, dict) and candidate.get("success") is True
                        and candidate.get("broker_returncode") == 0
                        and isinstance(candidate.get("result"), dict)
                        and candidate["result"].get("status") == "running"):
                        valid = True
                if not valid:
                    raise SystemExit("MainPID broker did not execute VM-only fixed file read: " + str(candidates)[:1000])
                print("original operator/MainPID/rootbroker positive VM action passed")
    asyncio.run(main())
  '';


  verifyOriginalPolicy = pkgs.writeText "grabowski-verify-original-policy.py" ''
    from pathlib import Path
    import sys
    import tempfile

    sys.path.insert(0, "${broker}/lib/grabowski")
    from grabowski_privileged_broker import load_root_config, resolve_regular_execution, claim_once

    config = load_root_config(Path("/etc/grabowski/privileged-actions.json"))
    assert config["schema_version"] == 2
    assert set(config["actions"]) == {"critical_user_data_inventory_read"}
    resolution = resolve_regular_execution(config, {
        "action": "critical_user_data_inventory_read", "target": "VM-only",
    })
    assert resolution["mode"] == "template"
    assert resolution["argv"] == ["${pkgs.coreutils}/bin/cat", "${benignResponseFile}"]
    assert resolution["allowed_peer_uid"] == 1000
    assert resolution["allowed_peer_unit"] == "grabowski-operator.service"
    try:
        resolve_regular_execution(config, {"action": "not-allowed", "target": "VM-only"})
    except PermissionError:
        pass
    else:
        raise SystemExit("original broker accepted an unlisted action")
    with tempfile.TemporaryDirectory() as temp:
        replay_dir = Path(temp) / "used"
        claim_once(replay_dir, "abcdef0123456789abcdef0123456789")
        try:
            claim_once(replay_dir, "abcdef0123456789abcdef0123456789")
        except FileExistsError:
            pass
        else:
            raise SystemExit("original broker replay guard admitted reuse")
    print("original policy loader, resolver, deny and replay checks passed")
  '';

  wrongMainPid = pkgs.writeText "grabowski-negative-wrong-mainpid.py" ''
    import grp
    import hashlib
    import json
    import os
    import pwd
    import socket
    import time

    now = int(time.time())
    reference = {
        "schema_version": 1,
        "execution": "unprivileged-reference-only",
        "may_execute": False,
        "requires_external_privileged_agent": True,
        "replay_policy": "single-use-external-broker",
        "action": "critical_user_data_inventory_read",
        "target": "VM-only",
        "justification": "Negative MainPID test on isolated virtual host",
        "request_id": "abcdefffabcdefffabcdefffabcdefff",
        "created_at_unix": now,
        "expires_at_unix": now + 60,
    }
    raw = json.dumps(reference, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    reference["reference_sha256"] = hashlib.sha256(raw).hexdigest()
    account = pwd.getpwnam("alex")
    os.setgroups([grp.getgrnam("grabowski").gr_gid])
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(25)
        client.connect("/run/grabowski/privileged-broker.sock")
        client.sendall(json.dumps(reference).encode())
        client.shutdown(socket.SHUT_WR)
        response = client.recv(65536)
    parsed = json.loads(response)
    if "systemd MainPID" not in parsed.get("error", ""):
        raise SystemExit("wrong-MainPID request was not rejected: " + repr(parsed))
    print("correct UID/group but wrong MainPID denied by original broker")
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
    # This VM has no physical Btrfs/Seagate partition. Use the SAME
    # virtualisation.fileSystems + fileSystems pattern as the existing
    # firstboot-credentials VM test: otherwise the NixOS test driver discards
    # /persist and our root policy start fails because persist.mount is absent.
    # This is an isolated ephemeral QEMU disk, never the physical Seagate.
    virtualisation.useDefaultFilesystems = true;
    virtualisation.emptyDiskImages = [ 256 ];
    virtualisation.fileSystems."/persist" = {
      device = "/dev/vdb";
      fsType = "ext4";
      autoFormat = true;
    };
    fileSystems."/persist" = {
      device = "/dev/vdb";
      fsType = "ext4";
    };
    systemd.services.grabowski-test-seed-policy = {
      description = "VM-only synthetic single-safe-action root-owned broker policy";
      requires = [ "persist.mount" ];
      after = [ "persist.mount" ];
      before = [ "grabowski-private-policy-install.service" ];
      serviceConfig = {
        Type = "oneshot";
        UMask = "0077";
        ExecStart = "${pkgs.writeShellScript "grabowski-test-seed-policy" ''
          set -eu
          ${pkgs.coreutils}/bin/install -d -m 0700 /persist/secrets /persist/secrets/grabowski
          ${pkgs.coreutils}/bin/install -m 0600 ${syntheticPolicy} /persist/secrets/grabowski/privileged-actions.json
          ${pkgs.coreutils}/bin/chmod 0600 /persist/secrets/grabowski/privileged-actions.json
        ''}";
      };
    };
    systemd.services.grabowski-private-policy-install = {
      requires = [ "grabowski-test-seed-policy.service" ];
      after = [ "grabowski-test-seed-policy.service" ];
    };
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
    for cmd in (
        "systemctl is-active persist.mount",
        "systemctl status grabowski-test-seed-policy.service --no-pager -l",
        "systemctl status grabowski-private-policy-install.service --no-pager -l",
        "systemctl status grabowski-privileged-broker.socket --no-pager -l",
        "journalctl -u grabowski-test-seed-policy.service -b --no-pager -n 50",
        "journalctl -u grabowski-private-policy-install.service -b --no-pager -n 50",
    ):
        code, output = machine.execute(cmd)
        print("PRIVATE-POLICY-DIAG:", cmd, "code", code, output[-5500:])
    machine.wait_until_succeeds(
        "systemctl is-active grabowski-private-policy-install.service", timeout=45,
    )
    with subtest("private source copied into root-only /etc before broker/socket activation"):
        machine.succeed("test -s /persist/secrets/grabowski/privileged-actions.json")
        machine.succeed("test -s /etc/grabowski/privileged-actions.json")
        machine.succeed("test $(stat -c %a /persist/secrets/grabowski) = 700")
        machine.succeed("test $(stat -c %a /persist/secrets/grabowski/privileged-actions.json) = 600")
        machine.succeed("test $(stat -c %a /etc/grabowski) = 755")
        machine.succeed("test $(stat -c %a /etc/grabowski/privileged-actions.json) = 600")
        machine.succeed("cmp /persist/secrets/grabowski/privileged-actions.json /etc/grabowski/privileged-actions.json")
        machine.succeed("${pkgs.python3}/bin/python3 ${verifyOriginalPolicy}")
        machine.succeed(
            "su -s ${pkgs.bash}/bin/bash -c "
            "'stat -c %U /etc/grabowski/privileged-actions.json | grep -qx root' alex"
        )
        machine.succeed(
            "su -s ${pkgs.bash}/bin/bash -c "
            "'test ! -r /etc/grabowski/privileged-actions.json' alex"
        )
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
        machine.succeed("${pkgs.python3}/bin/python3 ${wrongMainPid}")
        machine.succeed(
            "su -s ${pkgs.bash}/bin/bash -c "
            "'${pkgs.python3}/bin/python3 ${nonmemberNegative}' alex"
        )
        machine.succeed("test -s /etc/grabowski/privileged-actions.json")
  '';
}