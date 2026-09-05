{ config, lib, pkgs, ... }:
let
  guestCid = 445;
  brokerPort = 18446;
  capabilityManifest = {
    schema_version = 1;
    trust_zone = "untrusted-coding-agent";
    transport = {
      kind = "af_vsock";
      host_cid = 2;
      guest_cid = guestCid;
      broker_port = brokerPort;
      ip_network = false;
    };
    workspace = {
      model = "task-local-artifact";
      host_filesystem_share = false;
      result = "patch-and-evidence-only";
    };
    allow = [
      "broker.status"
      "workspace.import"
      "workspace.export_patch"
      "git.fetch"
      "github.read"
      "llm.request"
      "artifact.fetch"
    ];
    deny = [
      "host.shell"
      "host.filesystem"
      "home.read"
      "ssh.keys"
      "docker.sock"
      "systemd.host"
      "network.raw"
      "gpu.raw"
      "audio.raw"
      "rootbroker.unscoped"
    ];
  };
in
{
  networking.hostName = "agent-zone";
  networking.firewall.enable = true;

  # The production trust-zone model deliberately has no IP interface at all.
  # Agent-to-host communication is capability-mediated over AF_VSOCK. This is
  # intentionally stricter than the earlier QEMU user/NAT smoke proof.
  networking.useDHCP = false;

  environment.etc."heim-pc/agent-capabilities.json".text = builtins.toJSON capabilityManifest;
  environment.etc."heim-pc/trust-zone".text = "UNTRUSTED_AGENT_ZONE";
  environment.systemPackages = with pkgs; [ git jq ripgrep socat ];

  # Local proof only: establish that the guest is the untrusted side and that
  # its declared contract contains no ambient host or raw-device authority.
  systemd.services.agent-zone-contract-proof = {
    description = "Validate the fail-closed agent-zone capability contract";
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      Type = "oneshot";
      DynamicUser = true;
      NoNewPrivileges = true;
      ProtectSystem = "strict";
      ProtectHome = true;
      PrivateDevices = true;
      PrivateTmp = true;
      ProtectKernelTunables = true;
      ProtectKernelModules = true;
      ProtectControlGroups = true;
      RestrictSUIDSGID = true;
      RestrictRealtime = true;
      LockPersonality = true;
      MemoryDenyWriteExecute = true;
      RestrictAddressFamilies = [ "AF_UNIX" "AF_VSOCK" ];
      ExecStart = pkgs.writeShellScript "agent-zone-contract-proof" ''
        set -eu
        ${pkgs.jq}/bin/jq -e '.transport.kind == "af_vsock" and .transport.ip_network == false' /etc/heim-pc/agent-capabilities.json >/dev/null
        ${pkgs.jq}/bin/jq -e '.workspace.host_filesystem_share == false' /etc/heim-pc/agent-capabilities.json >/dev/null
        ${pkgs.jq}/bin/jq -e '.deny | index("gpu.raw") and index("audio.raw") and index("host.filesystem")' /etc/heim-pc/agent-capabilities.json >/dev/null
        test ! -e /etc/control-plane-secret
      '';
    };
  };

  microvm = {
    hypervisor = "qemu";
    mem = 1024;
    vcpu = 2;

    # Fail closed: no IP/NAT egress, no host directory sharing, and no raw
    # PCI/USB passthrough. A future task workspace must arrive as a dedicated
    # artifact/volume, never as an ambient host path.
    interfaces = [ ];
    forwardPorts = [ ];
    shares = [ ];
    devices = [ ];
    storeOnDisk = true;

    # CID 2 is the well-known host CID; this guest receives a stable, explicit
    # CID so Rootbroker/Bureau can bind authority to the VM identity.
    vsock.cid = guestCid;
  };

  assertions = [
    {
      assertion = config.microvm.interfaces == [ ];
      message = "agent-zone must not gain ambient IP networking";
    }
    {
      assertion = config.microvm.forwardPorts == [ ];
      message = "agent-zone must not gain implicit port forwarding";
    }
    {
      assertion = config.microvm.shares == [ ];
      message = "agent-zone must not share host directory trees";
    }
    {
      assertion = config.microvm.devices == [ ];
      message = "agent-zone must not receive raw PCI/USB devices";
    }
    {
      assertion = config.microvm.vsock.cid == guestCid;
      message = "agent-zone VSOCK identity drifted";
    }
  ];

  system.stateVersion = "26.05";
}
