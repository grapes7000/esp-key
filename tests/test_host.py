import os
import pathlib
import sys
import types
import unittest
from contextlib import contextmanager
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "host"))

import esp_key


class FakeSerial:
    port = "/dev/ttyACM0"

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class HostTests(unittest.TestCase):
    def test_zeroize_mutates_buffer(self):
        secret = bytearray(b"abc")
        esp_key.zeroize(secret)
        self.assertEqual(secret, bytearray(b"\0\0\0"))

    def test_memfd_contains_exact_key(self):
        key = bytearray(range(32))
        with esp_key.key_memfd(key) as (fd, path):
            self.assertTrue(path.startswith("/proc/self/fd/"))
            self.assertEqual(os.read(fd, 32), bytes(key))

    def test_derive_is_stable_and_empty_context_is_rejected(self):
        with mock.patch.object(esp_key, "command", return_value="HMAC " + "11" * 32):
            first = esp_key.derive(FakeSerial(), "test")
            second = esp_key.derive(FakeSerial(), "test")
        self.assertEqual(first, second)
        with self.assertRaises(esp_key.EspKeyError):
            esp_key.derive(FakeSerial(), "")
        esp_key.zeroize(first)
        esp_key.zeroize(second)

    def test_enroll_leaves_stdin_for_existing_passphrase(self):
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            return types.SimpleNamespace(returncode=0)

        @contextmanager
        def fake_connect(_):
            yield FakeSerial()

        with mock.patch.object(esp_key, "luks_uuid", return_value="abcd"), \
             mock.patch.object(esp_key, "connect", fake_connect), \
             mock.patch.object(esp_key, "derive", return_value=bytearray(b"K" * 32)), \
             mock.patch.object(esp_key.subprocess, "run", side_effect=fake_run):
            esp_key.cmd_enroll(types.SimpleNamespace(device="/tmp/vault", port=None))

        self.assertEqual(len(calls), 2)
        add_cmd, add_kwargs = calls[0]
        self.assertIn("luksAddKey", add_cmd)
        self.assertIn("--new-keyfile", add_cmd)
        self.assertNotIn("input", add_kwargs)
        self.assertTrue(add_kwargs.get("pass_fds"))

        verify_cmd, verify_kwargs = calls[1]
        self.assertIn("--test-passphrase", verify_cmd)
        self.assertIn("--key-file", verify_cmd)
        self.assertNotIn("input", verify_kwargs)

    def test_unlock_uses_memory_keyfile_not_stdin(self):
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            return types.SimpleNamespace(returncode=0)

        @contextmanager
        def fake_connect(_):
            yield FakeSerial()

        with mock.patch.object(esp_key, "luks_uuid", return_value="abcd"), \
             mock.patch.object(esp_key, "connect", fake_connect), \
             mock.patch.object(esp_key, "derive", return_value=bytearray(b"K" * 32)), \
             mock.patch.object(esp_key.subprocess, "run", side_effect=fake_run):
            esp_key.cmd_unlock(types.SimpleNamespace(device="/tmp/vault", name="vault", port=None))

        cmd, kwargs = calls[0]
        self.assertIn("--key-file", cmd)
        self.assertNotIn("input", kwargs)
        self.assertTrue(kwargs.get("pass_fds"))


if __name__ == "__main__":
    unittest.main()
