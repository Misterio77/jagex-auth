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

    checks = forAllSystems (system: let
      wrapperCheck = pkgsFor.${system}.callPackage ./tests/wrapper.nix {
        inherit (self.packages.${system}) jagex-auth;
      };
    in {
      package = self.packages.${system}.jagex-auth;
      launch = wrapperCheck;
      unfree-launch = wrapperCheck.override {clientLicense = nixpkgs.lib.licenses.unfree;};
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
