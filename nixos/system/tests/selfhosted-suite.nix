{ pkgs, physical, vm, prototype }:
let
  lib = pkgs.lib;
  cfg = physical.config;
  apps = [ "paperless" "audiobookshelf" "readeck" ];
  allOff = c: builtins.all (name: !c.services.${name}.enable) (apps ++ [ "immich" ]);
  disabled = physical.extendModules {
    modules = [ ({ lib, ... }: { heimPc.selfhostedSuite.enable = lib.mkForce false; }) ];
  };
  forcedVm = vm.extendModules {
    modules = [ { heimPc.selfhostedSuite = { enable = true; immich.enable = true; }; } ];
  };
  forcedPrototype = prototype.extendModules {
    modules = [ { heimPc.selfhostedSuite = { enable = true; immich.enable = true; }; } ];
  };
  headless = physical.extendModules {
    modules = [ ({ lib, ... }: { heimPc.desktop.enable = lib.mkForce false; }) ];
  };
  immich = physical.extendModules {
    modules = [ { heimPc.selfhostedSuite.immich.enable = true; } ];
  };
  ic = immich.config;
  ports = [ cfg.services.paperless.port cfg.services.audiobookshelf.port
    cfg.services.readeck.settings.server.port ic.services.immich.port ];
  stateNames = [ "audiobookshelf" "readeck" "redis-paperless" ];
in
assert builtins.all (name: cfg.services.${name}.enable) apps;
assert allOff vm.config && allOff forcedVm.config;
assert !cfg.services.immich.enable && !cfg.services.postgresql.enable;
assert !(cfg.services.redis.servers ? immich);
assert !(cfg.systemd.services ? immich-server);
assert !(builtins.tryEval ic.services.immich.package.outPath).success;
assert allOff forcedPrototype.config && allOff headless.config && allOff disabled.config;
assert !disabled.config.services.postgresql.enable;
assert !(disabled.config.services.redis.servers ? paperless);
assert cfg.services.paperless.address == "127.0.0.1";
assert cfg.services.audiobookshelf.host == "127.0.0.1";
assert cfg.services.readeck.settings.server.host == "127.0.0.1";
assert ic.services.immich.host == "127.0.0.1";
assert builtins.length (lib.unique ports) == 4;
assert builtins.all (p: !(builtins.elem p cfg.networking.firewall.allowedTCPPorts)) ports;
assert !cfg.services.audiobookshelf.openFirewall && !cfg.services.immich.openFirewall;
assert cfg.services.paperless.settings.PAPERLESS_DBHOST == "";
assert cfg.services.paperless.settings.PAPERLESS_OCR_LANGUAGE == "deu+eng";
assert !cfg.services.paperless.database.createLocally;
assert !cfg.services.paperless.consumptionDirIsPublic;
assert cfg.services.paperless.passwordFile == null;
assert !(cfg.services.paperless.settings ? PAPERLESS_AUTO_LOGIN_USERNAME);
assert builtins.all (path:
  cfg.systemd.tmpfiles.settings."10-paperless".${path}.d.mode == "0700"
) [ cfg.services.paperless.dataDir cfg.services.paperless.mediaDir cfg.services.paperless.consumptionDir ];
assert cfg.services.readeck.settings.database.source == "sqlite3:/var/lib/readeck/db.sqlite3";
assert cfg.systemd.services.readeck.serviceConfig.User == "readeck";
assert !cfg.systemd.services.readeck.serviceConfig.DynamicUser;
assert cfg.services.redis.package.pname == "valkey";
assert cfg.services.redis.servers.paperless.port == 0 && ic.services.redis.servers.immich.port == 0;
assert ic.services.immich.database.enable && ic.services.immich.database.createDB;
assert ic.services.immich.database.host == "/run/postgresql";
assert ic.services.postgresql.settings.listen_addresses == "";
assert !ic.services.postgresql.enableTCPIP;
assert !ic.services.immich.machine-learning.enable;
assert !ic.services.immich.settings.machineLearning.enabled;
assert !ic.services.immich.settings.library.scan.enabled;
assert !ic.services.immich.settings.library.watch.enabled;
assert ic.services.immich.accelerationDevices == [ ];
assert builtins.all (name:
  let sc = cfg.systemd.services.${name};
  in builtins.elem "/persist" sc.unitConfig.RequiresMountsFor
    && builtins.elem "/persist/selfhosted-suite/${name}:/var/lib/${name}" sc.serviceConfig.BindPaths
    && sc.serviceConfig.StateDirectoryMode == "0700"
    && sc.serviceConfig.UMask == "0077"
) stateNames;
assert lib.hasPrefix "/persist/selfhosted-suite/" ic.services.postgresql.dataDir;
assert lib.hasPrefix "/persist/selfhosted-suite/" cfg.services.paperless.dataDir;
assert builtins.elem "/persist" cfg.services.restic.backups.heim-pc.paths;
# Suite policy must leave the existing physical boot/storage/recovery contract alone.
assert cfg.fileSystems == disabled.config.fileSystems;
assert cfg.boot.loader.systemd-boot == disabled.config.boot.loader.systemd-boot;
assert cfg.boot.loader.efi == disabled.config.boot.loader.efi;
assert builtins.all (name:
  cfg.services.restic.backups.heim-pc.${name} == disabled.config.services.restic.backups.heim-pc.${name}
) [ "paths" "repository" "passwordFile" "extraBackupArgs" "backupPrepareCommand" "timerConfig" "pruneOpts" ];
pkgs.runCommand "heim-pc-selfhosted-suite-contract" { } ''
  touch "$out"
''
