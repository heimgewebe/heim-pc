{ pkgs, nixer }:
let
  clientPython = pkgs.python3.withPackages (ps: [ ps.mcp ]);
  verifyMcp = pkgs.writeText "nixer-headless-mcp-proof.py" ''
    import asyncio
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    expected = {
        "nixer_status", "flake_metadata", "flake_show", "flake_check",
        "eval_attr", "nixos_option", "derivation_show", "build_dry_run",
    }

    async def main():
        async with streamablehttp_client(
            "http://127.0.0.1:18187/mcp", timeout=15,
        ) as (read, write, *_):
            async with ClientSession(read, write) as session:
                await asyncio.wait_for(session.initialize(), timeout=30)
                response = await asyncio.wait_for(session.list_tools(), timeout=30)
                observed = {item.name for item in response.tools}
                if observed != expected:
                    raise SystemExit(
                        "Nixer original MCP surface changed: missing="
                        + str(sorted(expected - observed))
                        + " unexpected=" + str(sorted(observed - expected))
                    )
                status = await asyncio.wait_for(
                    session.call_tool("nixer_status", {}), timeout=30,
                )
                if getattr(status, "isError", False):
                    raise SystemExit("Nixer status rejected in headless system scope")
                print("verified original Nixer MCP in independent system service")

    asyncio.run(main())
  '';

  common = { pkgs, ... }: {
    imports = [
      nixer.nixosModules.default
      ../modules/nixer-headless.nix
    ];
    system.stateVersion = "26.05";
    networking.hostName = "nixer-headless-proof";
    users.groups.alex = { };
    users.users.alex = {
      isNormalUser = true;
      uid = 1000;
      group = "alex";
      home = "/home/alex";
      createHome = true;
      linger = false;
    };
    services.getty.autologinUser = null;
    virtualisation.podman.enable = true;
    heimPc.nixerHeadless.enable = true;
    virtualisation.memorySize = 3072;
    virtualisation.cores = 2;
    documentation.enable = false;
  };
in
pkgs.testers.runNixOSTest {
  name = "heim-pc-nixer-headless-systemd";
  globalTimeout = 1800;

  nodes = {
    # Exact production unit: no image in fresh VM => fail-closed start.
    missing = { ... }: { imports = [ common ]; };
    # Test-only override, NEVER a production preflight bypass. The real
    # package and real systemd MainPID are otherwise left unchanged.
    proof = { lib, pkgs, ... }: {
      imports = [ common ];
      systemd.services.nixer-headless.serviceConfig.ExecStartPre =
        lib.mkForce "${pkgs.coreutils}/bin/true";
    };
  };

  testScript = ''
    missing.start()
    missing.wait_for_unit("multi-user.target", timeout=180)
    with subtest("missing pinned OCI image denies headless Nixer start"):
        missing.wait_until_succeeds(
            "systemctl is-failed nixer-headless.service", timeout=150,
        )
        missing.fail("systemctl is-active nixer-headless.service")
        missing.succeed(
            "systemctl show nixer-headless.service --property=User "
            "--value | grep -qx alex"
        )
        missing.succeed(
            "systemctl show nixer-headless.service --property=ExecStartPre "
            "| grep -Fq heim-pc-nixer-check-image"
        )
    missing.shutdown()

    proof.start()
    proof.wait_for_unit("multi-user.target", timeout=180)
    with subtest("original Nixer starts as headless unprivileged system MainPID"):
        proof.wait_until_succeeds(
            "systemctl is-active nixer-headless.service", timeout=150,
        )
        pid = int(proof.succeed(
            "systemctl show nixer-headless.service "
            "--property=MainPID --value"
        ).strip())
        assert pid > 1
        proof.succeed(f"test $(stat -c %u /proc/{pid}) = 1000")
        proof.succeed("test $(stat -c %U /run/nixer-headless) = alex")
        proof.succeed("test $(stat -c %a /run/nixer-headless) = 700")
        proof.succeed(
            "systemctl show nixer-headless.service --property=MemoryMax "
            "--value | grep -qx 8589934592"
        )
        proof.succeed(
            "systemctl show nixer-headless.service --property=User "
            "--value | grep -qx alex"
        )
    with subtest("original eight-tool Nixer MCP initializes on localhost"):
        proof.wait_until_succeeds(
            "PYTHONDONTWRITEBYTECODE=1 "
            "${clientPython}/bin/python -B ${verifyMcp}",
            timeout=150,
        )
  '';
}
