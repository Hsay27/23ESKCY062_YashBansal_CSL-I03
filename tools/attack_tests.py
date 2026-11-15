"""
attack_tests.py - Plays the role of an attacker on the local lab network and
checks that the server rejects every attack.  Run ONLY against your own
server on your own machine / hotspot.

Usage:  python tools/attack_tests.py [--server http://127.0.0.1:5000]

Uses the test device "ESP32-TEST" so the real device's counter is untouched.
"""

import argparse
import base64
import copy
import csv
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from securepacket import build_packet, compute_mac, load_device_keys  # noqa: E402

DEVICE = "ESP32-TEST"
READING = {"temp_c": 26.5, "humidity": 48.0, "ts": 0}


def flip_bit(b64_text, byte_index):
    """Decode base64, flip the lowest bit of one byte, encode again."""
    raw = bytearray(base64.b64decode(b64_text))
    raw[byte_index] ^= 0x01
    return base64.b64encode(bytes(raw)).decode()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default="http://127.0.0.1:5000")
    args = ap.parse_args()
    url = args.server + "/api/v1/telemetry"

    keys = load_device_keys(ROOT / "server" / "devices.json")[DEVICE]
    aes_key, hmac_key = keys["aes_key"], keys["hmac_key"]
    # A sequence number that is always higher than in any earlier run.
    seq = int(time.time())

    def fresh(reading=READING):
        nonlocal seq
        seq += 1
        return build_packet(DEVICE, seq, reading, aes_key, hmac_key)

    results = []

    def run(test_id, name, body, expected, raw=False):
        if raw:
            r = requests.post(url, data=body, headers={"Content-Type": "application/json"})
        else:
            r = requests.post(url, json=body)
        reason = r.json().get("reason", r.json().get("status", "")) if r.content else ""
        ok = r.status_code == expected
        results.append((test_id, name, expected, r.status_code, reason, "PASS" if ok else "FAIL"))

    # TC-01 baseline: a correct packet must be accepted
    valid = fresh()
    run("TC-01", "Valid encrypted + signed packet", valid, 201)

    # TC-02 replay: attacker resends the captured packet unchanged
    run("TC-02", "Replay of captured packet", valid, 409)

    # TC-03 ciphertext tampering (bit flip in first ciphertext block)
    p = fresh(); p["ct"] = flip_bit(p["ct"], 0)
    run("TC-03", "Ciphertext modified (bit flip)", p, 401)

    # TC-04 IV tampering - in CBC this would change the decrypted data
    p = fresh(); p["iv"] = flip_bit(p["iv"], 3)
    run("TC-04", "IV modified (CBC bit-flip attack)", p, 401)

    # TC-05 change the counter so an old packet looks new
    p = copy.deepcopy(valid); p["seq"] = valid["seq"] + 1000
    run("TC-05", "Sequence number changed", p, 401)

    # TC-06 attacker does not know the key and forges a packet with his own key
    fake_key = bytes(16); fake_hmac = bytes(32)
    seq += 1
    forged = build_packet(DEVICE, seq, {"temp_c": 79.0, "humidity": 5.0, "ts": 0},
                          fake_key, fake_hmac)
    run("TC-06", "Forged packet with wrong keys", forged, 401)

    # TC-07 attacker keeps ciphertext but recomputes MAC with a guessed key
    p = fresh(); p["mac"] = compute_mac(b"guess" * 4, DEVICE, p["seq"], p["iv"], p["ct"])
    run("TC-07", "MAC recomputed with guessed key", p, 401)

    # TC-08 device spoofing: valid packet of ESP32-TEST relabelled as ESP32-01
    p = fresh(); p["device_id"] = "ESP32-01"
    run("TC-08", "Device ID spoofing", p, 401)

    # TC-09 unregistered device
    p = fresh(); p["device_id"] = "ROGUE-99"
    run("TC-09", "Unregistered device", p, 401)

    # TC-10 delayed / out-of-order packet (valid MAC, older seq)
    older = fresh(); newer = fresh()
    run("TC-10a", "Newer packet arrives first", newer, 201)
    run("TC-10b", "Older (delayed) packet afterwards", older, 409)

    # TC-11 missing MAC field
    p = fresh(); del p["mac"]
    run("TC-11", "MAC field removed", p, 400)

    # TC-12 not JSON at all
    run("TC-12", "Garbage body (not JSON)", "\x00\xffhello", 400, raw=True)

    # TC-13 authentic but physically impossible value (faulty sensor)
    run("TC-13", "Out-of-range value (temp 150 C)",
        fresh({"temp_c": 150.0, "humidity": 40.0, "ts": 0}), 422)

    # TC-14 second valid packet still accepted after all attacks
    run("TC-14", "Valid packet after attacks", fresh(), 201)

    # ---- print + save --------------------------------------------------
    print(f"{'ID':7}{'Test case':38}{'Expect':>7}{'Got':>5}  {'Reason':15}Result")
    print("-" * 82)
    for tid, name, exp, got, reason, res in results:
        print(f"{tid:7}{name:38}{exp:>7}{got:>5}  {reason:15}{res}")
    passed = sum(1 for r in results if r[-1] == "PASS")
    print("-" * 82)
    print(f"{passed}/{len(results)} test cases passed")

    out = ROOT / "results"; out.mkdir(exist_ok=True)
    with open(out / "attack_results.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "test_case", "expected", "actual", "reason", "result"])
        w.writerows(results)
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
