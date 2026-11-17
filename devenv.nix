{ pkgs, lib, config, inputs, ... }:

{
  # https://devenv.sh/packages/
  packages = [
    # Build
    pkgs.ko

    # Kubernetes
    pkgs.kubectl

    # Utilities
    pkgs.go-task
  ];

  # https://devenv.sh/languages/
  languages.go.enable = true;

  # See full reference at https://devenv.sh/reference/options/
}
