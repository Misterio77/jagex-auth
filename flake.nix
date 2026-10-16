{
  description = "Browser-based Jagex account authentication for existing RuneScape clients";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

  outputs = {
    self,
    nixpkgs,
  }: let
    systems = ["x86_64-linux" "aarch64-linux"];
    forAllSystems = nixpkgs.lib.genAttrs systems;
    # Wrappers inherit client licensing; the consumer must permit the client itself.
    pkgsFor = forAllSystems (system:
      import nixpkgs {
        inherit system;
        config.allowUnfree = true;
      });
  in {
    packages = forAllSystems (system: let
      jagex-auth = pkgsFor.${system}.callPackage ./. {};
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

    checks = forAllSystems (system: {
      package = self.packages.${system}.jagex-auth;
      launch = self.packages.${system}.jagex-auth.tests.launch;
      unfree-launch = import ./tests/wrapper.nix {
        inherit (pkgsFor.${system}) lib makeDesktopItem python3 runCommand symlinkJoin writeTextFile;
        jagex-auth = self.packages.${system}.jagex-auth;
        clientLicense = nixpkgs.lib.licenses.unfree;
      };
    });

    devShells = forAllSystems (system: let
      pkgs = pkgsFor.${system};
    in {
      default = pkgs.mkShellNoCC {
        packages = [pkgs.python3 pkgs.alejandra];
      };
    });

    formatter = forAllSystems (system: pkgsFor.${system}.alejandra);
  };
}
