{
  description = "keeweb-rs - A Rust-based KeePass password manager with Syncthing integration";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    treefmt-nix.url = "github:numtide/treefmt-nix";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs @ {
    self,
    nixpkgs,
    flake-parts,
    treefmt-nix,
    rust-overlay,
    ...
  }:
    flake-parts.lib.mkFlake {inherit inputs;} {
      imports = [
        treefmt-nix.flakeModule
        ./nix/rust.nix
      ];

      systems = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];

      perSystem = {
        config,
        self',
        inputs',
        pkgs,
        system,
        lib,
        ...
      }: let
        # Get the configured Rust toolchain from our module
        rustToolchain = config.keeweb-rs.rustToolchain;

        # Common build inputs for Rust projects
        buildInputs = with pkgs;
          [
            openssl
            pkg-config
          ]
          ++ lib.optionals stdenv.isDarwin [
            darwin.apple_sdk.frameworks.Security
            darwin.apple_sdk.frameworks.SystemConfiguration
          ];

        nativeBuildInputs = with pkgs; [
          pkg-config
          rustToolchain
        ];
      in {
        # Apply rust-overlay
        _module.args.pkgs = import nixpkgs {
          inherit system;
          overlays = [(import rust-overlay)];
        };

        # Configure treefmt for Rust and Nix formatting
        treefmt = {
          projectRootFile = "flake.nix";
          programs = {
            # Nix formatting
            alejandra.enable = true;
            # Rust formatting
            rustfmt = {
              enable = true;
              package = rustToolchain;
            };
          };
        };

        # Packages
        packages = {
          default = self'.packages.keeweb-server;

          keeweb-server = pkgs.rustPlatform.buildRustPackage {
            pname = "keeweb-server";
            version = "0.1.0";
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;

            inherit buildInputs nativeBuildInputs;

            cargoBuildFlags = ["-p" "keeweb-server"];

            meta = with lib; {
              description = "Optional backend server for keeweb-rs";
              homepage = "https://github.com/johnrichardrinehart/keeweb-rs";
              license = licenses.mit;
            };
          };

          keeweb-wasm = pkgs.rustPlatform.buildRustPackage {
            pname = "keeweb-wasm";
            version = "0.1.0";
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;

            nativeBuildInputs = nativeBuildInputs ++ [pkgs.wasm-pack pkgs.wasm-bindgen-cli];

            buildPhase = ''
              wasm-pack build crates/keeweb-wasm --target web --out-dir $out
            '';

            # Skip default cargo build
            dontCargoBuild = true;
            dontCargoInstall = true;

            meta = with lib; {
              description = "WASM bindings for keeweb-rs";
              homepage = "https://github.com/johnrichardrinehart/keeweb-rs";
              license = licenses.mit;
            };
          };

          keeweb-frontend = let
            # Create vendored cargo dependencies
            cargoVendorDir = pkgs.rustPlatform.importCargoLock {
              lockFile = ./Cargo.lock;
            };
          in pkgs.stdenv.mkDerivation {
            pname = "keeweb-frontend";
            version = "0.1.0";
            src = ./.;

            nativeBuildInputs =
              nativeBuildInputs
              ++ [
                pkgs.trunk
                pkgs.wasm-bindgen-cli
                pkgs.binaryen
              ];
            inherit buildInputs;

            buildPhase = ''
              export HOME=$(mktemp -d)

              # Set up vendored dependencies for cargo
              mkdir -p .cargo
              cat > .cargo/config.toml << EOF
              [source.crates-io]
              replace-with = "vendored-sources"

              [source.vendored-sources]
              directory = "${cargoVendorDir}"
              EOF

              # Create a Trunk.toml that uses the system wasm-bindgen version
              # trunk looks for wasm-bindgen in PATH when --offline is used
              cd frontend

              # Get the version of wasm-bindgen-cli we have
              WASM_BINDGEN_VERSION=$(wasm-bindgen --version | cut -d' ' -f2)
              echo "Using system wasm-bindgen version: $WASM_BINDGEN_VERSION"

              # Create Trunk.toml with matching version to prevent download
              cat > Trunk.toml << TOML
              [build]
              target = "index.html"
              dist = "dist"

              [tools]
              wasm_bindgen = "$WASM_BINDGEN_VERSION"
              wasm_opt = "version_123"

              [watch]
              watch = ["src", "index.html", "public"]
              ignore = ["dist"]
              TOML

              trunk build --release --public-url /keeweb-rs/ --offline
            '';

            installPhase = ''
              mkdir -p $out
              cp -r dist/* $out/
              # Add .nojekyll to prevent GitHub Pages from ignoring _files
              touch $out/.nojekyll
            '';

            meta = with lib; {
              description = "Web frontend for keeweb-rs password manager";
              homepage = "https://github.com/johnrichardrinehart/keeweb-rs";
              license = licenses.mit;
            };
          };
        };

        # Development shell
        devShells.default = pkgs.mkShell {
          inherit buildInputs;

          nativeBuildInputs =
            nativeBuildInputs
            ++ (with pkgs; [
              # Rust tools
              rust-analyzer
              cargo-watch
              cargo-edit
              cargo-audit

              # WASM tools
              wasm-pack
              wasm-bindgen-cli

              # Frontend tools
              trunk
              nodePackages.npm

              # Formatters (also available via nix fmt)
              config.treefmt.build.wrapper
            ]);

          RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";

          shellHook = ''
            echo "keeweb-rs development shell"
            echo "Rust version: $(rustc --version)"
            echo "Cargo version: $(cargo --version)"
            echo ""
            echo "Available commands:"
            echo "  cargo build          - Build the project"
            echo "  cargo test           - Run tests"
            echo "  cargo check          - Check compilation"
            echo "  nix fmt              - Format code (Rust + Nix)"
            echo "  nix flake check      - Run all checks including formatting"
            echo "  wasm-pack build      - Build WASM package"
            echo "  trunk serve          - Run frontend dev server (in frontend/)"
          '';
        };

        # Checks (run via nix flake check)
        checks = {
          # Formatting check
          formatting = config.treefmt.build.check self;

          # Cargo tests
          cargo-test = pkgs.stdenv.mkDerivation {
            name = "cargo-test";
            src = ./.;
            nativeBuildInputs = nativeBuildInputs;
            inherit buildInputs;
            buildPhase = ''
              export HOME=$(mktemp -d)
              cargo test --all
            '';
            installPhase = ''
              mkdir -p $out
              touch $out/success
            '';
          };

          # Clippy lints
          cargo-clippy = pkgs.stdenv.mkDerivation {
            name = "cargo-clippy";
            src = ./.;
            nativeBuildInputs = nativeBuildInputs;
            inherit buildInputs;
            buildPhase = ''
              export HOME=$(mktemp -d)
              cargo clippy --all -- -D warnings
            '';
            installPhase = ''
              mkdir -p $out
              touch $out/success
            '';
          };
        };
      };
    };
}
