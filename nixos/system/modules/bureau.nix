{ ... }:
{
  environment.etc."heim-pc/bureau-authority-boundary".text = ''Bureau authorizes reviewed desired-state changes.
This file grants no shell, root, service-start or mutation authority.
'';

  # Bureau owns the user service/timer. NixOS supplies only the platform
  # override for OpenSSH's /nix/store ownership checks in a user mount namespace.
  systemd.user.units."bureau-status-capsule.service" = {
    overrideStrategy = "asDropin";
    text = ''
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
  };
}
