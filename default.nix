{
  copyDesktopItems,
  lib,
  makeDesktopItem,
  makeWrapper,
  python3,
  stdenvNoCC,
  symlinkJoin,
}: let
  desktopItem = makeDesktopItem {
    name = "jagex-auth-handler";
    desktopName = "Jagex Auth URL Handler";
    exec = "jagex-auth handle-url %u";
    mimeTypes = ["x-scheme-handler/rshub"];
    noDisplay = true;
  };
in
  stdenvNoCC.mkDerivation (finalAttrs: {
    pname = "jagex-auth";
    version = "0-unstable";

    src = lib.fileset.toSource {
      root = ./.;
      fileset = lib.fileset.unions [
        ./jagex_auth
        ./LICENSE
        ./tests
      ];
    };

    doCheck = true;
    checkPhase = ''
      runHook preCheck
      PYTHONDONTWRITEBYTECODE=1 ${lib.getExe python3} -S -m unittest discover -s tests -v
      runHook postCheck
    '';

    nativeBuildInputs = [
      copyDesktopItems
      makeWrapper
    ];
    desktopItems = [desktopItem];

    installPhase = ''
      runHook preInstall

      install -Dm644 jagex_auth/__init__.py $out/share/jagex-auth/jagex_auth/__init__.py
      install -Dm644 jagex_auth/__main__.py $out/share/jagex-auth/jagex_auth/__main__.py
      install -Dm644 LICENSE $out/share/doc/jagex-auth/LICENSE
      makeWrapper ${lib.getExe python3} $out/bin/jagex-auth \
        --set PYTHONPATH $out/share/jagex-auth \
        --add-flags "-P -m jagex_auth"

      runHook postInstall
    '';

    passthru.wrapLaunch = package: let
      executable = package.meta.mainProgram or package.pname;
    in
      symlinkJoin {
        inherit (package) pname version;
        paths = [package];
        nativeBuildInputs = [makeWrapper];
        postBuild = ''
          rm "$out/bin/${executable}"
          makeWrapper ${lib.getExe finalAttrs.finalPackage} "$out/bin/${executable}" \
            --add-flags ${lib.escapeShellArg "launch -- ${package}/bin/${executable}"}
        '';
        inherit (package) meta;
        passthru = (package.passthru or {}) // {unwrapped = package;};
      };

    meta = {
      description = "Authenticate RuneScape clients with a Jagex account";
      mainProgram = "jagex-auth";
      license = lib.licenses.mit;
      platforms = lib.platforms.linux;
    };
  })
