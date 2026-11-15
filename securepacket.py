"""
securepacket.py - Secure packet format used by the ESP32 (and its simulator)
and by the server.

Project : Secure Sensor Data Transmission (ESP32 -> Server)   [CSL-I03]
Author  : Yash Bansal (23ESKCY062)

Packet sent over HTTP as JSON:

    {
      "device_id": "ESP32-01",          # which device sent it
      "seq":       42,                  # message counter (replay protection)
      "iv":        "<base64, 16 bytes>",# random IV, new for every message
      "ct":        "<base64>",          # AES-128-CBC ciphertext of the reading
      "mac":       "<hex, 64 chars>"    # HMAC-SHA256 tag
    }

    plaintext = {"temp_c": 27.4, "humidity": 51.2, "ts": 1762337000}
    ct        = AES-128-CBC(aes_key, iv, PKCS7(plaintext))
    mac       = HMAC-SHA256(hmac_key, "device_id|seq|iv|ct")

The MAC is calculated over the CIPHERTEXT (Encrypt-then-MAC), so the server
can reject a modified packet before it ever tries to decrypt it.
Two different keys are used: one only for AES, one only for HMAC.
"""

import base64
import binascii
import hashlib
import hmac
import json
import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

AES_KEY_LEN = 16    # AES-128
HMAC_KEY_LEN = 32   # 256-bit HMAC key
IV_LEN = 16         # AES block size
MAC_HEX_LEN = 64    # SHA-256 output = 32 bytes = 64 hex characters
MAX_SEQ = 2**32 - 1 # ESP32 stores the counter as a 32-bit unsigned number
MAX_CT_LEN = 1024   # sensor readings are small; reject anything huge


# --------------------------------------------------------------------------
# Errors. Each one has a short "reason" code that the server writes to its
# security log, e.g. "bad_mac" or "malformed".
# --------------------------------------------------------------------------
class PacketError(Exception):
    reason = "invalid"


class MalformedPacket(PacketError):
    reason = "malformed"


class AuthenticationFailed(PacketError):
    reason = "bad_mac"


class DecryptionFailed(PacketError):
    reason = "decrypt_error"


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def mac_input(device_id, seq, iv_b64, ct_b64):
    """The exact bytes that are signed. The ESP32 builds the same string."""
    return f"{device_id}|{seq}|{iv_b64}|{ct_b64}".encode("ascii")


def compute_mac(hmac_key, device_id, seq, iv_b64, ct_b64):
    """HMAC-SHA256 over the header fields and ciphertext, returned as hex."""
    return hmac.new(hmac_key, mac_input(device_id, seq, iv_b64, ct_b64),
                    hashlib.sha256).hexdigest()


def aes_encrypt(aes_key, plaintext, iv):
    """AES-128-CBC with PKCS#7 padding."""
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def aes_decrypt(aes_key, ciphertext, iv):
    """Reverse of aes_encrypt. Raises DecryptionFailed on bad padding."""
    decryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    try:
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError as exc:
        raise DecryptionFailed("bad padding") from exc


# --------------------------------------------------------------------------
# Sender side (ESP32 simulator / tests)
# --------------------------------------------------------------------------
def build_packet(device_id, seq, reading, aes_key, hmac_key, iv=None):
    """Encrypt and sign one sensor reading. Returns the packet (dict)."""
    plaintext = json.dumps(reading, separators=(",", ":")).encode()
    iv = iv if iv is not None else os.urandom(IV_LEN)  # fresh random IV
    ciphertext = aes_encrypt(aes_key, plaintext, iv)

    iv_b64 = base64.b64encode(iv).decode("ascii")
    ct_b64 = base64.b64encode(ciphertext).decode("ascii")
    return {
        "device_id": device_id,
        "seq": seq,
        "iv": iv_b64,
        "ct": ct_b64,
        "mac": compute_mac(hmac_key, device_id, seq, iv_b64, ct_b64),
    }


# --------------------------------------------------------------------------
# Receiver side (server)
# --------------------------------------------------------------------------
def parse_fields(packet):
    """Check that every field exists and has the right type and size.
    Nothing here is trusted yet - the MAC has not been checked."""
    if not isinstance(packet, dict):
        raise MalformedPacket("packet is not a JSON object")
    for name in ("device_id", "seq", "iv", "ct", "mac"):
        if name not in packet:
            raise MalformedPacket(f"missing field '{name}'")

    device_id, seq = packet["device_id"], packet["seq"]
    iv_b64, ct_b64, mac = packet["iv"], packet["ct"], packet["mac"]

    if not isinstance(device_id, str) or not (1 <= len(device_id) <= 32) \
            or not device_id.isascii() or "|" in device_id:
        raise MalformedPacket("bad device_id")
    # bool is a subclass of int in Python, so exclude it explicitly
    if isinstance(seq, bool) or not isinstance(seq, int) or not (1 <= seq <= MAX_SEQ):
        raise MalformedPacket("bad seq")
    if not all(isinstance(v, str) for v in (iv_b64, ct_b64, mac)):
        raise MalformedPacket("iv/ct/mac must be strings")
    if len(mac) != MAC_HEX_LEN:
        raise MalformedPacket("bad mac length")
    if len(ct_b64) > MAX_CT_LEN * 2:
        raise MalformedPacket("ciphertext too large")
    return {"device_id": device_id, "seq": seq, "iv": iv_b64, "ct": ct_b64, "mac": mac}


def verify_and_decrypt(fields, aes_key, hmac_key):
    """1) verify HMAC (constant time) 2) decode 3) decrypt 4) parse JSON.
    Returns the reading dict, or raises a PacketError subclass."""
    expected = compute_mac(hmac_key, fields["device_id"], fields["seq"],
                           fields["iv"], fields["ct"])
    received = fields["mac"].lower()
    # compare_digest takes the same time whether the first or the last
    # byte is wrong, so an attacker cannot guess the MAC byte by byte.
    if not hmac.compare_digest(expected.encode(),
                               received.encode("utf-8")):
        raise AuthenticationFailed("HMAC does not match")

    # Only authentic data reaches this point.
    try:
        iv = base64.b64decode(fields["iv"], validate=True)
        ciphertext = base64.b64decode(fields["ct"], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise MalformedPacket("bad base64") from exc
    if (len(iv) != IV_LEN or len(ciphertext) == 0
            or len(ciphertext) % 16 != 0):
        raise MalformedPacket("bad iv or ciphertext length")

    plaintext = aes_decrypt(aes_key, ciphertext, iv)
    try:
        reading = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecryptionFailed("plaintext is not valid JSON") from exc
    if not isinstance(reading, dict):
        raise DecryptionFailed("plaintext is not a JSON object")
    return reading


def load_device_keys(path):
    """Read devices.json -> {device_id: {"aes_key": bytes, "hmac_key": bytes}}"""
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    devices = {}
    for device_id, keys in raw.items():
        aes_key = bytes.fromhex(keys["aes_key"])
        hmac_key = bytes.fromhex(keys["hmac_key"])
        if len(aes_key) != AES_KEY_LEN or len(hmac_key) != HMAC_KEY_LEN:
            raise ValueError(f"wrong key length for device {device_id}")
        devices[device_id] = {"aes_key": aes_key, "hmac_key": hmac_key}
    return devices
