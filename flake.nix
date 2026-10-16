{
  description = "Browser-based Jagex account authentication for existing RuneScape clients";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

  outputs = {
    self,
    nixpkgs,
  }: let
    systems = ["x86_64-linux" "aarch64-linux"];
    forAllSystems = nixpkgs.lib.genAttrs systems;
  in {
    packages = forAllSystems (system: let
      # Wrappers inherit client licensing; the consumer must permit the client itself.
      pkgs = import nixpkgs {
        inherit system;
        config.allowUnfree = true;
      };
      jagex-auth = pkgs.callPackage ./. {};
    in {
      inherit jagex-auth;
      default = jagex-auth;
    });

    apps = forAllSystems (system: let
      app = {
        type = "app";
        program = nixpkgs.lib.getExe self.packages.${system}.jagex-auth;
        meta.description = self.packages.${system}.jagex-auth.meta.description;
      };
    in {
      jagex-auth = app;
      default = app;
    });

    checks = forAllSystems (system: let
      consumerPkgs = import nixpkgs {
        inherit system;
        config.allowUnfree = true;
      };
    in {
      package = self.packages.${system}.jagex-auth;
      launch = self.packages.${system}.jagex-auth.tests.launch;
      unfree-launch = import ./tests/wrapper.nix {
        inherit (consumerPkgs) lib makeDesktopItem python3 runCommand symlinkJoin writeTextFile;
        jagex-auth = self.packages.${system}.jagex-auth;
        clientLicense = consumerPkgs.lib.licenses.unfree;
      };
    });

    devShells = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      default = pkgs.mkShellNoCC {
        packages = [pkgs.python3 pkgs.alejandra];
      };
    });

    formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.alejandra);
  };
}
