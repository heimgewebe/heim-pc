{ config, lib, ... }:
let
  cfg = config.heimPc.hardware.nvidia;
in
{
  options.heimPc.hardware.nvidia = {
    enable = lib.mkEnableOption "RTX 4070 Ti Super NVIDIA/CUDA host profile";
    openKernelModule = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Use NVIDIA's open kernel module for the physical Gate-A A/B proof.";
    };
  };

  config = lib.mkIf cfg.enable {
    services.xserver.videoDrivers = [ "nvidia" ];
    hardware.graphics.enable = true;
    hardware.nvidia = {
      modesetting.enable = true;
      open = cfg.openKernelModule;
      nvidiaSettings = true;
      package = config.boot.kernelPackages.nvidiaPackages.stable;
    };
    hardware.nvidia-container-toolkit.enable = true;
  };
}
