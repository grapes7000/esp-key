import pathlib
import sys
import types
import unittest
from contextlib import contextmanager
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "host"))

import auto_unlock
import esp_key


class AutoUnlockTests(unittest.TestCase):
    def test_validation(self):
        uuid = "d88890c9-3af1-4c80-90a5-d26468225e39"
        self.assertEqual(auto_unlock.validate_uuid(uuid.upper()), uuid)
        self.assertEqual(auto_unlock.validate_mapper("esp-key-usb"), "esp-key-usb")

    def test_already_active_short_circuits(self):
        with mock.patch.object(auto_unlock, "mapper_active", return_value=True), \
             mock.patch.object(auto_unlock, "luks_device") as luks_device:
            self.assertEqual(
                auto_unlock.unlock_once(
                    "d88890c9-3af1-4c80-90a5-d26468225e39", "esp-key-usb"
                ),
                "already-active",
            )
            luks_device.assert_not_called()

    def test_missing_volume_is_normal(self):
        with mock.patch.object(auto_unlock, "mapper_active", return_value=False), \
             mock.patch.object(auto_unlock, "luks_device", return_value=None):
            self.assertEqual(
                auto_unlock.unlock_once(
                    "d88890c9-3af1-4c80-90a5-d26468225e39", "esp-key-usb"
                ),
                "volume-missing",
            )

    def test_unlock_uses_uuid_bound_key_and_zeroizes(self):
        class FakeSerial:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False

        key = bytearray(b"K" * 32)
        result = types.SimpleNamespace(returncode=0)

        with mock.patch.object(auto_unlock, "mapper_active", return_value=False), \
             mock.patch.object(auto_unlock, "luks_device", return_value="/dev/sda"), \
             mock.patch.object(esp_key, "connect", return_value=FakeSerial()), \
             mock.patch.object(esp_key, "derive", return_value=key) as derive, \
             mock.patch.object(esp_key, "run_with_keyfile", return_value=result) as run:
            state = auto_unlock.unlock_once(
                "d88890c9-3af1-4c80-90a5-d26468225e39", "esp-key-usb"
            )

        self.assertEqual(state, "unlocked")
        derive.assert_called_once_with(
            mock.ANY, "luks:d88890c9-3af1-4c80-90a5-d26468225e39"
        )
        self.assertIn("/dev/sda", run.call_args.args[0])
        self.assertEqual(key, bytearray(32))


if __name__ == "__main__":
    unittest.main()
