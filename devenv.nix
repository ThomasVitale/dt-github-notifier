{ pkgs, lib, config, inputs, ... }:

{
  # https://devenv.sh/packages/
  packages = [
    # Build
    pkgs.crane
    pkgs.ko

    # Code quality
    pkgs.golangci-lint
    pkgs.govulncheck

    # Kubernetes
    pkgs.kubectl

    # Utilities
    pkgs.cosign
    pkgs.go-task
    pkgs.jq
  ];

  # https://devenv.sh/languages/
  languages.go.enable = true;

  # See full reference at https://devenv.sh/reference/options/
}
