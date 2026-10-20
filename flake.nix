{
  description = "wick -- zero-knowledge one-time secret sharer";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.cargo
            pkgs.rustc
            pkgs.rustfmt
            pkgs.clippy
            pkgs.rust-analyzer
            pkgs.sqlx-cli
            pkgs.pkg-config
            pkgs.openssl
            pkgs.sqlite
          ];

          shellHook = ''
            mkdir -p data
            export RUST_LOG=''${RUST_LOG:-wick=debug,tower_http=debug}
          '';
        };
      });
}
