# jagex-auth

A small, unofficial Jagex-account authentication helper for existing RuneScape
clients. Uses your normal browser, then starts a compatible client with the
`JX_SESSION_ID`, `JX_CHARACTER_ID`, and `JX_DISPLAY_NAME` environment variables.
It does not download/update clients or fix RS3's GTK2/OpenSSL dependencies.

See [SECURITY.md](SECURITY.md) for the server-validation trust boundary and
callback lifetime details. It is not affiliated with Jagex.

## Usage

With the `rshub` desktop URL handler registered to Jagex Auth URL Handler:

```sh
jagex-auth authorize
jagex-auth launch -- runelite
jagex-auth launch -- hdos
jagex-auth launch -- runescape
```

Authorize opens your browser and prompts for a character if needed. Characters
without a display name are skipped; set a character name first if none are named.
If browser callback delivery does not work, paste the successful-login URL into the terminal
running `authorize`. Treat that URL as a secret; it is echoed like any other
terminal input. Installing the desktop file does
not necessarily register it as the default handler; check your desktop's URL
associations. Do not replace an existing handler without considering its users.
Raw ID tokens are not accepted: paste the complete successful-login URL so its
state can be checked. Run one authorization at a time (there is no locking;
the last one to finish wins). The wait times out after five minutes. Ctrl-C
cancels the attempt.

`launch` never prompts or opens a browser. It requires existing credentials;
if absent or invalid it asks you to run `authorize`. An expired/revoked game
session may instead be rejected by the game: authorize again. There is no
automatic session refresh or local check that a saved session is still valid.
Arguments following the command are passed through literally. `launch` replaces
itself with the client, preserving signal and exit-status behavior.

ID tokens are not signature-verified locally. The helper only checks that the
response is bound to its own request (state and nonce), then relies on Jagex's
HTTPS session exchange and character listing to establish authentication before
saving a login.

For direct Python use (Python 3.10+ on Linux; standard library only), run from
the source directory:

```sh
python3 -m jagex_auth authorize
python3 -m jagex_auth launch -- runelite
```

Browser callback integration additionally requires installing an appropriate
`.desktop` handler for `jagex-auth handle-url %u`. The Nix package supplies one.

## Nix

Run directly from GitHub:

```sh
nix run github:Misterio77/jagex-auth -- --help
nix run github:Misterio77/jagex-auth -- authorize
```

Or from a checkout:

```sh
nix run . -- --help
nix run . -- authorize
nix build .
./result/bin/jagex-auth --help
# Optional installation, including the desktop handler:
nix profile add .
```

The flake exposes `packages.<system>.{default,jagex-auth}` for `x86_64-linux`
and `aarch64-linux`. The package's `wrapLaunch` function wraps an
existing client. Add this input to your flake:

```nix
{
  inputs.jagex-auth = {
    url = "github:Misterio77/jagex-auth";
    inputs.nixpkgs.follows = "nixpkgs";
  };
}
```

A Home Manager module can then use:

```nix
{inputs, pkgs, ...}: let
  jagexAuth = inputs.jagex-auth.packages.${pkgs.stdenv.hostPlatform.system}.default;
in {
  home.packages = [
    jagexAuth
    (jagexAuth.wrapLaunch pkgs.runelite)
  ];
}
```

Following `nixpkgs` shares its revision, not your package configuration.
`pkgs.callPackage /path/to/jagex-auth {}` also works without using this flake.

The returned package preserves the client's desktop files and wraps its main
executable with `jagex-auth launch -- <original-executable>`. Authentication is
runtime-only; credentials never become Nix inputs or store contents. In-game
login was verified with the RuneLite 2.8.0 launcher, HDOS launcher 8, and RS3
2.2.12 package on 2026-10-16. This does not guarantee that other versions or
systems satisfy each client's runtime dependencies.

## Storage

Credentials live in `$XDG_DATA_HOME/jagex-auth/credentials.json`, defaulting to
`~/.local/share/jagex-auth/credentials.json`. The file holds the three `JX_*`
fields; unknown keys are ignored. The directory is private (`0700`); credential files are
created private (`0600`) and replaced atomically. Unsafe credential file types,
symlinks, files owned by another user, and group/world permissions are rejected.

Only the JSON format is supported; there is no legacy detection or migration.
Run `jagex-auth authorize` to create credentials. Do not paste credentials into
bug reports. On impermanent systems, persist the data directory if you want
sessions to survive a reboot.

Credentials are ordinary data, never shell code. They are passed to clients
through the environment, not command arguments. This is not protection from
processes running as your user (which may also read your files or environment).
Keep the account, browser profile, and machine secure. Logging out of this tool
is not yet implemented; deleting local files does not revoke a server session.

## Offline checks

```sh
# -S disables site packages, demonstrating that tests need only the stdlib:
PYTHONDONTWRITEBYTECODE=1 python3 -S -m unittest discover -s tests -v
# Build the package (including Python tests) and fake-client wrapper check:
nix flake check
# Optional development environment and formatter:
nix develop
nix fmt ./flake.nix ./default.nix ./tests/wrapper.nix
```

Tests use synthetic credentials and temporary directories, block unexpected
network/browser calls, and exercise process launching without starting a game.
Never use real credentials in fixtures.

## License and provenance

[MIT](LICENSE), Copyright (c) 2026 Gabriel Fontes.

Originally developed in [Foundry](https://github.com/Misterio77/Foundry).
