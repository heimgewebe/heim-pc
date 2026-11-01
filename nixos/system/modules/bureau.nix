{ ... }:
{
  environment.etc."heim-pc/bureau-authority-boundary".text = ''Bureau authorizes reviewed desired-state changes.
This file grants no shell, root, service-start or mutation authority.
'';

  # Bureau owns the user service/timer. NixOS supplies only the platform
  # override for OpenSSH's /nix/store ownership checks in a user mount namespace.
  environment.etc."systemd/user/bureau-status-capsule.service.d/20-nixos-ssh-owner.conf".text = ''
    [Service]
    # NixOS systemd --user mount namespaces map root-owned /nix/store SSH config
    # files to uid 65534; OpenSSH rejects that ownership. Preserve the
    # non-filesystem process protections from the original unit.
    ProtectSystem=no
    ProtectHome=no
    PrivateTmp=no
    ReadOnlyPaths=
    ReadWritePaths=
  '';
}
