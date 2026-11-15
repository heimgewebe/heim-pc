{ config, lib, pkgs, ... }:
let
  cfg = config.heimPc.selfhostedSuite;
  eligible = config.heimPc.day2Activation.enable
    && config.heimPc.desktop.enable
    && builtins.hasAttr "/persist" config.fileSystems;
  root = "/persist/selfhosted-suite";
  # Keep native StateDirectory paths inside each service's mount namespace.
  # The backing directories belong to the existing @persist/Restic scope.
  persistentState = name: {
    unitConfig.RequiresMountsFor = [ "/persist" ];
    serviceConfig = {
      BindPaths = [ "${root}/${name}:/var/lib/${name}" ];
      StateDirectoryMode = "0700";
      UMask = "0077";
    };
  };
in
{
  options.heimPc.selfhostedSuite = {
    enable = lib.mkEnableOption "the local-only self-hosted application suite";
    immich.enable = lib.mkEnableOption ''
      Immich after a reviewed supported package is available (the pinned
      immich-2.7.5 is insecure and intentionally stays disabled)
    '';
  };

  config = lib.mkIf (cfg.enable && eligible) {
    services.paperless = {
      enable = true;
      address = "127.0.0.1";
      port = 28981;
      dataDir = "${root}/paperless";
      mediaDir = "${root}/paperless/media";
      consumptionDir = "${root}/paperless/consume";
      consumptionDirIsPublic = false;
      database.createLocally = false;
      configureNginx = false;
      configureTika = false;
      # No password/default account in Git or the Store. Initialize locally
      # with the native paperless-manage createsuperuser command after deploy.
      settings = {
        # Paperless selects SQLite when DBHOST is empty (DBENGINE only
        # distinguishes PostgreSQL/MariaDB when a database host is supplied).
        PAPERLESS_DBHOST = "";
        PAPERLESS_OCR_LANGUAGE = "deu+eng";
        PAPERLESS_TASK_WORKERS = 1;
        PAPERLESS_THREADS_PER_WORKER = 2;
      };
    };

    services.audiobookshelf = {
      enable = true;
      host = "127.0.0.1";
      port = 13378;
      openFirewall = false;
      # Native empty state; no preconfigured libraries or home-directory scan.
    };

    services.readeck = {
      enable = true;
      settings = {
        server = { host = "127.0.0.1"; port = 8001; };
        database.source = "sqlite3:/var/lib/readeck/db.sqlite3";
        main.data_directory = "/var/lib/readeck/data";
      };
    };

    services.immich = lib.mkIf cfg.immich.enable {
      enable = true;
      host = "127.0.0.1";
      port = 2283;
      openFirewall = false;
      database = { enable = true; createDB = true; host = "/run/postgresql"; };
      redis.enable = true;
      machine-learning.enable = false;
      accelerationDevices = [ ];
      settings = {
        machineLearning.enabled = false;
        library = { scan.enabled = false; watch.enabled = false; };
        map.enabled = false;
        reverseGeocoding.enabled = false;
        newVersionCheck.enabled = false;
        # Native scheduled dumps use *.sql.gz, explicitly excluded by the
        # existing Restic contract. Do not imply these provide restore proof.
        backup.database.enabled = false;
      };
    };

    services.postgresql = lib.mkIf cfg.immich.enable {
      dataDir = "${root}/postgresql/${config.services.postgresql.package.psqlSchema}";
      # Immich authenticates as its OS user using the native peer/Unix socket.
      settings.listen_addresses = lib.mkForce "";
      enableTCPIP = false;
    };

    services.redis = {
      package = pkgs.valkey;
      servers.paperless = { port = 0; openFirewall = false; };
      servers.immich = lib.mkIf cfg.immich.enable { port = 0; openFirewall = false; };
    };

    # Readeck's native DynamicUser cannot own a stable external backing path.
    # Retain its native sandbox with a dedicated, non-login system identity.
    users.users.readeck = { isSystemUser = true; group = "readeck"; };
    users.groups.readeck = { };
    systemd.services = {
      audiobookshelf = lib.mkMerge [
        (persistentState "audiobookshelf")
        { serviceConfig = { ProtectHome = true; ProtectSystem = "strict"; NoNewPrivileges = true; PrivateTmp = true; }; }
      ];
      readeck = lib.mkMerge [
        (persistentState "readeck")
        { serviceConfig = { DynamicUser = lib.mkForce false; User = "readeck"; Group = "readeck"; ProtectHome = true; }; }
      ];
      immich-server = lib.mkIf cfg.immich.enable (persistentState "immich");
      redis-paperless = persistentState "redis-paperless";
      redis-immich = lib.mkIf cfg.immich.enable (persistentState "redis-immich");
    };

    systemd.tmpfiles.rules = [
      "d ${root} 0711 root root -"
      "d ${root}/audiobookshelf 0700 audiobookshelf audiobookshelf -"
      "d ${root}/audiobookshelf/library 0700 audiobookshelf audiobookshelf -"
      "d ${root}/readeck 0700 readeck readeck -"
      "d ${root}/redis-paperless 0700 redis-paperless redis-paperless -"
    ] ++ lib.optionals cfg.immich.enable [
      "d ${root}/immich 0700 immich immich -"
      "d ${root}/redis-immich 0700 redis-immich redis-immich -"
      "d ${root}/postgresql 0700 postgres postgres -"
      "d ${config.services.postgresql.dataDir} 0700 postgres postgres -"
    ];
    systemd.tmpfiles.settings."10-paperless" = {
      "${config.services.paperless.dataDir}".d.mode = "0700";
      "${config.services.paperless.mediaDir}".d.mode = "0700";
      "${config.services.paperless.consumptionDir}".d.mode = "0700";
    };
  };
}
