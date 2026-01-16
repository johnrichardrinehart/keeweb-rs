# Rust toolchain configuration flake module
# Allows overriding cargo and rustc versions through flakeModule options
{
  lib,
  flake-parts-lib,
  ...
}: {
  options.perSystem = flake-parts-lib.mkPerSystemOption ({
    config,
    pkgs,
    lib,
    ...
  }: {
    options.keeweb-rs = {
      rustVersion = lib.mkOption {
        type = lib.types.str;
        default = "stable";
        description = ''
          The Rust version to use. Can be:
          - "stable" for latest stable
          - "beta" for beta channel
          - "nightly" for nightly channel
          - A specific version like "1.75.0"
        '';
        example = "1.75.0";
      };

      rustProfile = lib.mkOption {
        type = lib.types.str;
        default = "default";
        description = ''
          The Rust profile to use (default, minimal, complete).
        '';
        example = "minimal";
      };

      rustExtensions = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [
          "rust-src"
          "rust-analyzer"
          "clippy"
          "rustfmt"
        ];
        description = ''
          Additional Rust extensions to include in the toolchain.
        '';
        example = ["rust-src" "llvm-tools-preview"];
      };

      rustTargets = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = ["wasm32-unknown-unknown"];
        description = ''
          Additional compilation targets to include.
        '';
        example = ["wasm32-unknown-unknown" "aarch64-unknown-linux-gnu"];
      };

      rustToolchain = lib.mkOption {
        type = lib.types.package;
        readOnly = true;
        description = ''
          The configured Rust toolchain package. This is automatically
          derived from the other options.
        '';
      };
    };

    config.keeweb-rs.rustToolchain = let
      cfg = config.keeweb-rs;

      # Build the toolchain based on configuration
      toolchain =
        if cfg.rustVersion == "stable"
        then
          pkgs.rust-bin.stable.latest.${cfg.rustProfile}.override {
            extensions = cfg.rustExtensions;
            targets = cfg.rustTargets;
          }
        else if cfg.rustVersion == "beta"
        then
          pkgs.rust-bin.beta.latest.${cfg.rustProfile}.override {
            extensions = cfg.rustExtensions;
            targets = cfg.rustTargets;
          }
        else if cfg.rustVersion == "nightly"
        then
          pkgs.rust-bin.nightly.latest.${cfg.rustProfile}.override {
            extensions = cfg.rustExtensions;
            targets = cfg.rustTargets;
          }
        else
          # Specific version
          pkgs.rust-bin.stable.${cfg.rustVersion}.${cfg.rustProfile}.override {
            extensions = cfg.rustExtensions;
            targets = cfg.rustTargets;
          };
    in
      toolchain;
  });
}
