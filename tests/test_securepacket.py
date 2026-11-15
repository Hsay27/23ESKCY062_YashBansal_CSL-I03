"""
Unit tests for securepacket.py   ->   python -m unittest -v tests/test_securepacket.py
"""

import base64
import hashlib
import hmac
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from securepacket import (AuthenticationFailed, MalformedPacket, aes_decrypt,  # noqa: E402
                          aes_encrypt, build_packet, compute_mac, parse_fields,
                          verify_and_decrypt)

AES_KEY, HMAC_KEY = os.urandom(16), os.urandom(32)
READING = {"temp_c": 27.4, "humidity": 51.2, "ts": 1762337000}


class TestSecurePacket(unittest.TestCase):

    def test_round_trip(self):
        p = build_packet("ESP32-01", 1, READING, AES_KEY, HMAC_KEY)
        self.assertEqual(verify_and_decrypt(parse_fields(p), AES_KEY, HMAC_KEY), READING)

    def test_ciphertext_hides_plaintext(self):
        p = build_packet("ESP32-01", 1, READING, AES_KEY, HMAC_KEY)
        self.assertNotIn(b"temp_c", base64.b64decode(p["ct"]))

    def test_random_iv_gives_different_ciphertext(self):
        a = build_packet("ESP32-01", 1, READING, AES_KEY, HMAC_KEY)
        b = build_packet("ESP32-01", 1, READING, AES_KEY, HMAC_KEY)
        self.assertNotEqual(a["iv"], b["iv"])
        self.assertNotEqual(a["ct"], b["ct"])

    def test_known_answer_aes(self):
        # NIST SP 800-38A F.2.1 CBC-AES128 first block
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        block = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        ct = aes_encrypt(key, block, iv)
        self.assertEqual(ct[:16].hex(), "7649abac8119b246cee98e9b12e9197d")
        self.assertEqual(aes_decrypt(key, ct, iv), block)

    def test_mac_framing(self):
        # The signed string must be exactly "device_id|seq|iv|ct" -
        # the ESP32 firmware builds the same string with snprintf().
        mac = compute_mac(b"key", "D", 1, "aXY=", "Y3Q=")
        self.assertEqual(mac, hmac.new(b"key", b"D|1|aXY=|Y3Q=", hashlib.sha256).hexdigest())

    def test_tampered_ciphertext_rejected(self):
        p = build_packet("ESP32-01", 1, READING, AES_KEY, HMAC_KEY)
        raw = bytearray(base64.b64decode(p["ct"])); raw[0] ^= 1
        p["ct"] = base64.b64encode(bytes(raw)).decode()
        with self.assertRaises(AuthenticationFailed):
            verify_and_decrypt(parse_fields(p), AES_KEY, HMAC_KEY)

    def test_changed_seq_rejected(self):
        p = build_packet("ESP32-01", 1, READING, AES_KEY, HMAC_KEY)
        p["seq"] = 2
        with self.assertRaises(AuthenticationFailed):
            verify_and_decrypt(parse_fields(p), AES_KEY, HMAC_KEY)

    def test_wrong_hmac_key_rejected(self):
        p = build_packet("ESP32-01", 1, READING, AES_KEY, HMAC_KEY)
        with self.assertRaises(AuthenticationFailed):
            verify_and_decrypt(parse_fields(p), AES_KEY, os.urandom(32))

    def test_missing_field(self):
        p = build_packet("ESP32-01", 1, READING, AES_KEY, HMAC_KEY)
        del p["iv"]
        with self.assertRaises(MalformedPacket):
            parse_fields(p)

    def test_bad_seq_types(self):
        for bad in (0, -5, "7", True, 2**32, 1.5):
            p = build_packet("ESP32-01", 1, READING, AES_KEY, HMAC_KEY)
            p["seq"] = bad
            with self.assertRaises(MalformedPacket, msg=repr(bad)):
                parse_fields(p)


if __name__ == "__main__":
    unittest.main(verbosity=2)
