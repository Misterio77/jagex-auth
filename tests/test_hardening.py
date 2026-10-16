"""Offline token, callback, race, timeout, and cancellation regression tests."""

import argparse
from email.message import Message
import io
import json
import os
import signal
import subprocess
import sys
import time
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request
import urllib.response

import jagex_auth as auth
from test_auth import AuthTestCase, encode_token, token


class HardeningTests(AuthTestCase):
    def handle(self, url):
        auth.handle_url(argparse.Namespace(url=url))

    def test_inconsistent_unverified_claims(self):
        changes = [
            {"iss": "https://evil.invalid/"}, {"aud": "wrong"},
            {"exp": int(time.time()) - 120}, {"iat": int(time.time()) + 120},
            {"exp": None}, {"iat": True}, {"nbf": "0"},
            {"nonce": "wrong"}, {"nonce": None},
            {"sub": ""}, {"nickname": []}, {"azp": "wrong"},
            {"aud": [auth.CLIENT_ID, "other"]},
        ]
        for claims in changes:
            with self.subTest(claims=claims), self.assertRaises(SystemExit):
                auth.decode_id_token(token(claims), "nonce")

    def test_missing_required_claims(self):
        for claim in ("exp", "iat", "sub", "iss", "aud", "nonce"):
            value = auth.decode_id_token(token(), "nonce")
            del value[claim]
            with self.subTest(claim=claim), self.assertRaises(SystemExit):
                auth.decode_id_token(encode_token(value), "nonce")

    def test_decoding_is_not_signature_verification_and_never_fetches_keys(self):
        # An arbitrary signature passes local consistency checks, not login.
        encoded = token(headers={"alg": "RS256", "kid": "unknown", "jku": "https://evil.invalid/"})
        with patch.object(auth, "request_json") as request:
            self.assertEqual(auth.decode_id_token(encoded, "nonce")["sub"], "subject")
        request.assert_not_called()

    def test_server_rejection_or_failed_character_listing_never_saves_login(self):
        auth.write_credentials("existing", {"accountId": "c", "displayName": "Name"})
        before = auth.CREDENTIALS_FILE.read_bytes()
        id_token = token({"nickname": "UNTRUSTED"})
        for failed_step in ("session", "characters"):
            with (
                patch.object(auth.secrets, "token_urlsafe", side_effect=["state", "nonce"]),
                patch.object(auth, "open_browser"),
                patch.object(auth, "wait_for_authentication", return_value=self.callback(state="state", id_token=id_token)),
                patch.object(auth, "get_game_session", side_effect=SystemExit("rejected") if failed_step == "session" else None, return_value="session") as exchange,
                patch.object(auth, "get_accounts", side_effect=SystemExit("rejected")) as accounts,
                patch.object(auth, "write_credentials") as write,
                self.assertRaises(SystemExit),
            ):
                auth.authorize(None)
            exchange.assert_called_once_with(id_token)
            if failed_step == "session":
                accounts.assert_not_called()
            else:
                accounts.assert_called_once_with("session")
            write.assert_not_called()
            self.assertEqual(auth.CREDENTIALS_FILE.read_bytes(), before)
            self.assertNotIn("Authenticated", self.output.getvalue())
            self.assertNotIn("UNTRUSTED", self.output.getvalue())

    def test_strict_urls_and_parameters(self):
        valid = self.callback(state="s", id_token="id")
        for value in (
            token(), valid + "&state=s", valid + "&id_token=other",
            valid.replace("rshub://auth", "rshub://user@auth"),
            valid.replace("/callback", "/callback?query=1"),
            valid.replace("/callback", "/callback/"),
            auth.REDIRECT_URI.replace("/en-GB/", "/wrong/") + "#state=s&id_token=id",
            valid + "\n", valid + "&broken", valid + "&x=%FF",
            valid.replace("state=s", "state=%C3%A9"),
            valid.replace("state=s", "state=é"),
            self.callback(state="s", error="access_denied"),
            self.callback(state="s"), "x" * (auth.MAX_CALLBACK + 1),
        ):
            with self.subTest(value=value[:70]), self.assertRaises(SystemExit):
                auth.authentication_params(value, "s")

    def test_unsolicited_mismatched_and_repeated_callbacks(self):
        with self.assertRaisesRegex(SystemExit, "No active"):
            self.handle(self.callback(state="s", id_token="id"))
        auth.ensure_data_dir()
        auth.atomic_write_private(auth.PENDING_FILE, "[]")
        with self.assertRaisesRegex(SystemExit, "Invalid authorization state"):
            self.handle(self.callback(state="s", id_token="id"))
        with auth.authorization_attempt() as (state, _):
            with self.assertRaisesRegex(SystemExit, "state mismatch"):
                self.handle(self.callback(state="wrong", id_token="id"))
            self.assertFalse(auth.CALLBACK_FILE.exists())
            self.handle(self.callback(state=state, id_token="first"))
            latest = self.callback(state=state, id_token="second")
            self.handle(latest)  # Last delivery wins; nothing is locked.
            self.assertEqual(auth.wait_for_authentication(timeout=1), latest)
            self.assertFalse(auth.CALLBACK_FILE.exists())

    def test_new_attempt_replaces_stale_state(self):
        # A killed authorizer leaves files behind; the next attempt replaces them.
        auth.ensure_data_dir()
        auth.atomic_write_private(auth.PENDING_FILE, json.dumps({"state": "stale"}))
        auth.atomic_write_private(auth.CALLBACK_FILE, json.dumps({"url": "stale"}))
        with auth.authorization_attempt() as (state, _):
            self.assertNotEqual(state, "stale")
            self.assertEqual(auth.read_private_json(auth.PENDING_FILE), {"state": state})
            self.assertFalse(auth.CALLBACK_FILE.exists())
        self.assertFalse(auth.PENDING_FILE.exists())

    def test_closed_stdin_timeout_and_cleanup(self):
        class NoStdin:
            def fileno(self):
                raise ValueError("closed")
        with self.assertRaisesRegex(SystemExit, "timed out"):
            with auth.authorization_attempt(), patch.object(auth.sys, "stdin", NoStdin()):
                auth.wait_for_authentication(timeout=0.02)
        self.assertFalse(auth.PENDING_FILE.exists())
        self.assertFalse(auth.CALLBACK_FILE.exists())

    def test_partial_stdin_is_bounded_and_manual_url_works(self):
        read, write = os.pipe()
        self.addCleanup(os.close, write)
        stream = os.fdopen(read, "rb")
        self.addCleanup(stream.close)
        with auth.authorization_attempt() as (state, _), patch.object(auth.sys, "stdin", stream):
            os.write(write, self.callback(state=state, id_token="id").encode() + b"\n")
            self.assertIn("id_token=id", auth.wait_for_authentication(timeout=0.5))
            os.write(write, b"partial-without-newline")
            with self.assertRaisesRegex(SystemExit, "timed out"):
                auth.wait_for_authentication(timeout=0.02)

    def test_failed_and_interrupted_login_preserve_credentials(self):
        auth.write_credentials("existing", {"accountId": "c", "displayName": "Name"})
        before = auth.CREDENTIALS_FILE.read_bytes()
        for failure in (KeyboardInterrupt(), EOFError(), SystemExit("failed")):
            with patch.object(auth, "open_browser", side_effect=failure), self.assertRaises(SystemExit):
                auth.authorize(None)
            self.assertEqual(auth.CREDENTIALS_FILE.read_bytes(), before)
            self.assertFalse(auth.PENDING_FILE.exists())
            self.assertFalse(auth.CALLBACK_FILE.exists())

    def test_http_errors_do_not_echo_secrets(self):
        error = urllib.error.HTTPError("https://test.invalid", 403, "Forbidden", {}, io.BytesIO(b"SECRET_TOKEN"))
        with patch.object(auth.HTTP_OPENER, "open", side_effect=error), self.assertRaises(SystemExit) as caught:
            auth.request_json("https://test.invalid")
        self.assertNotIn("SECRET_TOKEN", str(caught.exception))
        with patch.object(auth.HTTP_OPENER, "open", return_value=io.BytesIO(b"x" * 1048577)), self.assertRaises(SystemExit):
            auth.request_json("https://test.invalid")

    def test_deeply_nested_json_is_rejected(self):
        nested = "[" * 12000 + "0" + "]" * 12000
        with patch.object(auth.HTTP_OPENER, "open", return_value=io.BytesIO(nested.encode())), self.assertRaises(SystemExit):
            auth.get_game_session("synthetic-token")
        auth.ensure_data_dir()
        auth.atomic_write_private(auth.CREDENTIALS_FILE, nested)
        with self.assertRaisesRegex(SystemExit, "Invalid or unsafe"):
            auth.read_credentials()

    def test_redirects_never_forward_credentials(self):
        calls = []

        class FakeTransport(urllib.request.HTTPSHandler, urllib.request.HTTPHandler):
            def https_open(self, request):
                calls.append(request)
                headers = Message()
                headers["Location"] = "http://evil.invalid/steal"
                response = urllib.response.addinfourl(io.BytesIO(b""), headers, request.full_url, 302)
                response.msg = "Found"
                return response

            http_open = https_open

        opener = urllib.request.build_opener(auth.NoRedirects(), FakeTransport())
        with patch.object(auth, "HTTP_OPENER", opener), self.assertRaisesRegex(SystemExit, "HTTP 302"):
            auth.request_json(auth.ACCOUNTS_ENDPOINT, headers={"Authorization": "Bearer synthetic-secret"})
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].full_url, auth.ACCOUNTS_ENDPOINT)

    def test_interrupt_after_save_does_not_claim_credentials_unchanged(self):
        original = auth.write_credentials

        def save_then_interrupt(*args):
            original(*args)
            raise KeyboardInterrupt()

        with (
            patch.object(auth.secrets, "token_urlsafe", side_effect=["state", "nonce"]),
            patch.object(auth, "open_browser"),
            patch.object(auth, "wait_for_authentication", return_value=self.callback(state="state", id_token=token())),
            patch.object(auth, "get_game_session", return_value="new-session"),
            patch.object(auth, "get_accounts", return_value=[{"accountId": "c", "displayName": "Name"}]),
            patch.object(auth, "write_credentials", side_effect=save_then_interrupt),
            self.assertRaises(SystemExit) as caught,
        ):
            auth.authorize(None)
        self.assertNotIn("unchanged", str(caught.exception))
        self.assertEqual(auth.read_credentials()["JX_SESSION_ID"], "new-session")
        self.assertFalse(auth.PENDING_FILE.exists())

    def test_invalid_manual_input_is_rejected(self):
        read, write = os.pipe()
        self.addCleanup(os.close, write)
        stream = os.fdopen(read, "rb")
        self.addCleanup(stream.close)
        for chunk, message in ((b"\xff\n", "encoding"), (b"x" * (auth.MAX_CALLBACK + 1), "too large")):
            with self.subTest(message=message), auth.authorization_attempt(), patch.object(auth.sys, "stdin", stream):
                with patch.object(auth.select, "select", return_value=([read], [], [])), patch.object(auth.os, "read", return_value=chunk):
                    with self.assertRaisesRegex(SystemExit, message):
                        auth.wait_for_authentication(timeout=1)

    def test_initialization_interruption_cleans_published_state(self):
        original = auth.atomic_write_private

        def publish_then_interrupt(path, contents):
            original(path, contents)
            if path == auth.PENDING_FILE:
                raise KeyboardInterrupt()

        with patch.object(auth, "atomic_write_private", side_effect=publish_then_interrupt), self.assertRaises(KeyboardInterrupt):
            with auth.authorization_attempt():
                self.fail("Initialization should have been interrupted")
        self.assertFalse(auth.PENDING_FILE.exists())
        self.assertFalse(auth.CALLBACK_FILE.exists())

    def test_terminal_paste_is_read_as_one_line(self):
        master, slave = os.openpty()
        self.addCleanup(os.close, master)
        stream = os.fdopen(slave, "rb")
        self.addCleanup(stream.close)
        with auth.authorization_attempt() as (state, _), patch.object(auth.sys, "stdin", stream):
            url = self.callback(state=state, id_token="a" * 1500)
            os.write(master, url.encode() + b"\n")
            self.assertEqual(auth.wait_for_authentication(timeout=1), url)

    def test_sigterm_cleans_attempt_and_restores_handler(self):
        previous = signal.getsignal(signal.SIGTERM)
        with self.assertRaises(SystemExit) as caught:
            with auth.cancellation_signals(), auth.authorization_attempt():
                os.kill(os.getpid(), signal.SIGTERM)
        self.assertEqual(caught.exception.code, 143)
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous)
        self.assertFalse(auth.PENDING_FILE.exists())

    def test_cross_process_callback_delivery(self):
        with auth.authorization_attempt() as (state, _):
            result = subprocess.run([sys.executable, "-m", "jagex_auth", "handle-url", self.callback(state=state, id_token="id")], env=self.env, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("id_token=id", auth.wait_for_authentication(timeout=1))
        result = subprocess.run([sys.executable, "-m", "jagex_auth", "handle-url", self.callback(state="s", id_token="id")], env=self.env, capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("No active authorization", result.stderr)


if __name__ == "__main__":
    unittest.main()
