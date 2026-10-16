import argparse
import base64
from contextlib import contextmanager
import json
import os
import secrets
import select
import signal
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path

AUTH_ENDPOINT = "https://account.jagex.com/oauth2/auth"
CLIENT_ID = "com_jagex_auth_desktop_launcher_rs_hub"
REDIRECT_URI = "https://account.jagex.com/en-GB/launcher/successful-login"
SESSION_ENDPOINT = "https://auth.runescape.com/game-session/v1/sessions"
ACCOUNTS_ENDPOINT = "https://auth.runescape.com/game-session/v2/accounts"
AUTH_TIMEOUT = 300
MAX_CALLBACK = 16384
MAX_PRIVATE_JSON = 65536

DATA_DIR = (
    Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "jagex-auth"
)
CALLBACK_FILE = DATA_DIR / "auth-callback.json"
PENDING_FILE = DATA_DIR / "pending.json"
CREDENTIALS_FILE = DATA_DIR / "credentials.json"
CREDENTIAL_KEYS = ("JX_SESSION_ID", "JX_CHARACTER_ID", "JX_DISPLAY_NAME")


def ensure_data_dir() -> None:
    DATA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    DATA_DIR.chmod(0o700)  # A persisted directory may have been created with a loose mode.


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Fixed authentication endpoints must not redirect tokens or credentials.
        return None


HTTP_OPENER = urllib.request.build_opener(NoRedirects())


def request_json(
    url: str,
    *,
    method: str = "GET",
    body: dict | None = None,
    headers: dict[str, str] | None = None,
) -> dict | list:
    request_headers = {"Accept": "application/json", **(headers or {})}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        request_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        url,
        data=data,
        headers=request_headers,
        method=method,
    )
    try:
        with HTTP_OPENER.open(request, timeout=30) as response:
            raw = response.read(1048577)
            if len(raw) > 1048576:
                raise SystemExit("Authentication server response too large")
            result = json.loads(raw)
    except urllib.error.HTTPError as err:
        # Authentication error responses can contain secrets. Never echo bodies.
        err.close()
        raise SystemExit(f"HTTP {err.code} from {url}") from None
    except (urllib.error.URLError, TimeoutError):
        raise SystemExit(f"Request failed for {url}") from None
    except (ValueError, RecursionError) as err:
        raise SystemExit(f"Invalid JSON from {url}") from err
    if not isinstance(result, (dict, list)):
        raise SystemExit(f"Invalid JSON from {url}")
    return result


def make_auth_url(state: str, nonce: str) -> str:
    params = {
        "redirect_uri": REDIRECT_URI,
        "response_type": "id_token",
        "client_id": CLIENT_ID,
        "scope": "openid",
        "state": state,
        "nonce": nonce,
    }
    return f"{AUTH_ENDPOINT}?{urllib.parse.urlencode(params)}"


def open_browser(url: str) -> None:
    if not webbrowser.open(url):
        print(f"Open this URL manually:\n{url}", file=sys.stderr)


def response_url(value: str) -> urllib.parse.ParseResult:
    if not isinstance(value, str) or len(value) > MAX_CALLBACK or any(ord(c) < 32 for c in value):
        raise SystemExit("Invalid Jagex authentication response")
    try:
        parsed = urllib.parse.urlparse(value)
    except ValueError:
        raise SystemExit("Invalid Jagex authentication response") from None
    origin = parsed._replace(fragment="").geturl()
    if origin not in {"rshub://auth/callback", REDIRECT_URI}:
        raise SystemExit("Invalid Jagex authentication response URL")
    return parsed


def authentication_params(value: str, expected_state: str) -> dict[str, str]:
    parsed = response_url(value)
    try:
        pairs = urllib.parse.parse_qsl(
            parsed.fragment, keep_blank_values=True, strict_parsing=True,
            max_num_fields=16, errors="strict",
        )
    except (ValueError, UnicodeError):
        raise SystemExit("Invalid authentication response parameters") from None
    params = dict(pairs)
    if len(params) != len(pairs):
        raise SystemExit("Duplicate authentication response parameters")
    if not expected_state or not secrets.compare_digest(
        params.get("state", "").encode("utf-8"), expected_state.encode("utf-8")
    ):
        raise SystemExit("OAuth state mismatch")
    if "error" in params:
        raise SystemExit("Jagex declined authentication; please try again")
    if not params.get("id_token"):
        raise SystemExit("Jagex authentication response did not contain an ID token")
    return params


def wait_for_authentication(timeout: float = AUTH_TIMEOUT) -> str:
    # shortcut: canonical tty lines cap at 4095 bytes; callback URLs are ~1.5 KiB today. Revisit if they grow.
    print("Waiting for browser callback; you can also paste the successful-login URL here:", file=sys.stderr)
    deadline = time.monotonic() + timeout
    buffer = b""
    try:
        stdin = sys.stdin.fileno()
    except (AttributeError, ValueError, OSError):
        stdin = None
    while time.monotonic() < deadline:
        try:
            callback = read_private_json(CALLBACK_FILE, MAX_CALLBACK * 2)
        except FileNotFoundError:
            callback = None
        if callback is not None:
            if not isinstance(callback, dict) or not isinstance(callback.get("url"), str):
                raise SystemExit("Invalid browser callback file")
            CALLBACK_FILE.unlink(missing_ok=True)
            return callback["url"]
        if stdin is None:
            time.sleep(0.1)
            continue
        readable, _, _ = select.select([stdin], [], [], 0.1)
        if readable:
            chunk = os.read(stdin, MAX_CALLBACK + 1)
            buffer += chunk
            if len(buffer) > MAX_CALLBACK:
                raise SystemExit("Authentication response too large")
            if b"\n" in buffer or (not chunk and buffer):
                try:
                    return buffer.split(b"\n", 1)[0].rstrip(b"\r").decode("utf-8")
                except UnicodeError:
                    raise SystemExit("Invalid authentication response encoding") from None
            if not chunk:
                stdin = None
    raise SystemExit("Authentication timed out; run 'jagex-auth authorize' again")


def check_nonce(token: str, nonce: str) -> None:
    """Bind the token to this attempt. This is NOT signature verification.

    Only Jagex's session exchange and character listing establish authentication;
    every other claim is left to the server, which enforces them anyway.
    """
    try:
        parts = token.split(".")
        if len(token) > MAX_CALLBACK or len(parts) != 3:
            raise ValueError("Invalid JWT")
        payload = json.loads(base64.b64decode(parts[1] + "=" * (-len(parts[1]) % 4), altchars=b"-_", validate=True))
        if not isinstance(payload, dict):
            raise ValueError("Invalid JWT payload")
    except (ValueError, RecursionError):
        raise SystemExit("Malformed Jagex ID token") from None
    if not isinstance(payload.get("nonce"), str) or not secrets.compare_digest(
        payload["nonce"].encode("utf-8"), nonce.encode("utf-8")
    ):
        raise SystemExit("OAuth nonce mismatch")


def get_game_session(id_token: str) -> str:
    result = request_json(
        SESSION_ENDPOINT,
        method="POST",
        body={"idToken": id_token},
    )
    session_id = result.get("sessionId") if isinstance(result, dict) else None
    if not isinstance(session_id, str) or not session_id or any(ord(c) < 32 for c in session_id):
        raise SystemExit("Jagex did not return a game session ID")
    return session_id


def get_accounts(session_id: str) -> list[dict]:
    result = request_json(
        ACCOUNTS_ENDPOINT,
        headers={"Authorization": f"Bearer {session_id}"},
    )
    if not isinstance(result, list) or not result:
        raise SystemExit("No RuneScape characters found")
    if any(
        not isinstance(account, dict)
        or not isinstance(account.get("accountId"), str)
        or not account["accountId"]
        or any(ord(c) < 32 for c in account["accountId"])
        or (account.get("displayName") is not None and (
            not isinstance(account["displayName"], str)
            or any(ord(c) < 32 for c in account["displayName"])
        ))
        for account in result
    ):
        raise SystemExit("Invalid RuneScape character information")
    named = [account for account in result if account.get("displayName")]
    if not named:
        raise SystemExit("No named RuneScape characters found; set a character name and authorize again")
    if len(named) != len(result):
        print("Skipping characters without a display name.", file=sys.stderr)
    return named


def choose_account(accounts: list[dict]) -> dict:
    if len(accounts) == 1:
        return accounts[0]

    print("\nAvailable RuneScape characters:", file=sys.stderr)
    for index, account in enumerate(accounts, start=1):
        print(f"  {index}. {account['displayName']} ({account['accountId']})", file=sys.stderr)

    while True:
        try:
            choice = int(input("Character number: "))
            if 1 <= choice <= len(accounts):
                return accounts[choice - 1]
        except ValueError:
            pass
        print("Invalid character number", file=sys.stderr)


def validate_credentials(value: object) -> dict[str, str]:
    if (
        not isinstance(value, dict)
        or type(value.get("version")) is not int
        or value["version"] != 1
        or set(value) != {"version", *CREDENTIAL_KEYS}
        or any(
            not isinstance(value[key], str) or not value[key] or "\0" in value[key]
            for key in CREDENTIAL_KEYS
        )
    ):
        raise ValueError("Invalid credential schema")
    return {key: value[key] for key in CREDENTIAL_KEYS}


def atomic_write_private(path: Path, contents: str) -> None:
    # mkstemp creates the file with 0600, even under a permissive umask.
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def write_credentials(session_id: str, account: dict) -> None:
    values = {
        "version": 1,
        "JX_SESSION_ID": session_id,
        "JX_CHARACTER_ID": account.get("accountId"),
        "JX_DISPLAY_NAME": account.get("displayName"),
    }
    try:
        validate_credentials(values)
        contents = json.dumps(values, ensure_ascii=False) + "\n"
        if len(contents.encode("utf-8")) > MAX_PRIVATE_JSON:
            raise SystemExit("Credentials too large; existing credentials were not replaced")
    except ValueError:
        raise SystemExit("Invalid session or selected character information") from None
    ensure_data_dir()
    try:
        atomic_write_private(CREDENTIALS_FILE, contents)
    except OSError:
        raise SystemExit("Could not save credentials; existing credentials were not replaced") from None


def read_private_json(path: Path, limit: int = MAX_PRIVATE_JSON):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "r", encoding="utf-8") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or info.st_size > limit
        ):
            raise ValueError("Unsafe or oversized private file")
        contents = stream.read(limit + 1)
        if len(contents) > limit:
            raise ValueError("Private file too large")
        try:
            return json.loads(contents)
        except RecursionError:
            raise ValueError("Private JSON nesting too deep") from None


def read_credentials() -> dict[str, str]:
    try:
        return validate_credentials(read_private_json(CREDENTIALS_FILE))
    except FileNotFoundError:
        message = "No saved credentials"
    except (OSError, ValueError):
        message = "Invalid or unsafe saved credentials"
    raise SystemExit(f"{message}; run 'jagex-auth authorize'.")


def launch(args: argparse.Namespace) -> None:
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise SystemExit("Usage: jagex-auth launch -- COMMAND [ARG ...]")
    environment = {**os.environ, **read_credentials()}
    try:
        os.execvpe(command[0], command, environment)
    except FileNotFoundError:
        print("Client executable not found", file=sys.stderr)
        raise SystemExit(127) from None
    except OSError:
        print("Could not execute client", file=sys.stderr)
        raise SystemExit(126) from None


@contextmanager
def authorization_attempt():
    # No locking: one authorization at a time is assumed, and a newer attempt replaces older state.
    ensure_data_dir()
    try:
        CALLBACK_FILE.unlink(missing_ok=True)
        state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        atomic_write_private(PENDING_FILE, json.dumps({"state": state}))
        yield state, nonce
    finally:
        PENDING_FILE.unlink(missing_ok=True)
        CALLBACK_FILE.unlink(missing_ok=True)


@contextmanager
def cancellation_signals():
    def terminate(signum, _frame):
        raise SystemExit(128 + signum)

    previous = signal.signal(signal.SIGTERM, terminate)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


def authorize(_args: argparse.Namespace) -> None:
    try:
        with cancellation_signals(), authorization_attempt() as (state, nonce):
            print("Opening Jagex login in your browser.", file=sys.stderr)
            open_browser(make_auth_url(state, nonce))
            params = authentication_params(wait_for_authentication(), state)
            check_nonce(params["id_token"], nonce)
            session_id = get_game_session(params["id_token"])
            account = choose_account(get_accounts(session_id))
            write_credentials(session_id, account)
            print(f"Authenticated as {account['displayName']}.", file=sys.stderr)
    except (KeyboardInterrupt, EOFError):
        raise SystemExit("Authorization cancelled; credentials may already have been saved") from None
    except (OSError, ValueError):
        raise SystemExit("Could not access authorization state safely; please retry") from None


def handle_url(args: argparse.Namespace) -> None:
    try:
        pending = read_private_json(PENDING_FILE)
    except FileNotFoundError:
        raise SystemExit("No active authorization; run 'jagex-auth authorize'") from None
    except (OSError, ValueError):
        raise SystemExit("Could not read authorization state; run 'jagex-auth authorize' again") from None
    if not isinstance(pending, dict) or not isinstance(pending.get("state"), str) or not pending["state"]:
        raise SystemExit("Invalid authorization state; run 'jagex-auth authorize' again")
    authentication_params(args.url, pending["state"])
    try:
        atomic_write_private(CALLBACK_FILE, json.dumps({"url": args.url}))
    except OSError:
        raise SystemExit("Could not deliver the authentication response; please retry") from None


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="jagex-auth",
        description="Authenticate RuneScape clients with a Jagex account",
    )
    commands = parser.add_subparsers(required=True)

    commands.add_parser("authorize", help="authenticate with Jagex").set_defaults(func=authorize)

    callback_parser = commands.add_parser(
        "handle-url", help="receive the browser authentication callback"
    )
    callback_parser.add_argument("url")
    callback_parser.set_defaults(func=handle_url)

    launch_parser = commands.add_parser(
        "launch", help="launch a client using saved credentials (noninteractive)"
    )
    launch_parser.add_argument("command", nargs=argparse.REMAINDER)
    launch_parser.set_defaults(func=launch)

    args = parser.parse_args()
    args.func(args)

