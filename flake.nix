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
      jagex-auth = nixpkgs.legacyPackages.${system}.callPackage ./. {};
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
