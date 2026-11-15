"""
app.py - Receiving server for secure ESP32 sensor data.

Run:   python server/app.py                 (secure endpoint only)
       python server/app.py --allow-plain   (also enable the INSECURE
                                             baseline endpoint, used only to
                                             compare captures in Wireshark)

Endpoints
  POST /api/v1/telemetry        secure packets (AES + HMAC) from devices
  POST /api/v1/telemetry/plain  plaintext baseline (disabled by default)
  GET  /api/v1/readings         stored readings as JSON
  GET  /                        dashboard

Order of checks for every secure packet:
  1. JSON + field format        -> 400 malformed
  2. device_id is registered    -> 401 unknown_device
  3. HMAC-SHA256 is correct     -> 401 bad_mac
  4. AES decrypt + JSON parse   -> 400 decrypt_error
  5. values in sensor range     -> 422 out_of_range
  6. seq > last accepted seq    -> 409 replay
  7. store in SQLite            -> 201 accepted
"""

import argparse
import logging
import sys
from pathlib import Path

from flask import Flask, jsonify, render_template, request

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR.parent))      # so we can import securepacket

import storage                                 # noqa: E402
from securepacket import (AuthenticationFailed, PacketError,  # noqa: E402
                          load_device_keys, parse_fields, verify_and_decrypt)

# Physical range of the DHT22 sensor. Authentic but impossible values are
# rejected too (a faulty sensor should not pollute the database).
LIMITS = {"temp_c": (-40.0, 80.0), "humidity": (0.0, 100.0)}

app = Flask(__name__)
app.config["ALLOW_PLAIN"] = False
DEVICES = {}
log = logging.getLogger("secure-server")


def reject(status, reason, device_id=None, detail=""):
    """Log a rejected request (file + database) and send a short error.
    The client is told only the reason code, never key or MAC details."""
    ip = request.remote_addr
    log.warning("REJECT %-14s device=%s ip=%s %s", reason, device_id, ip, detail)
    storage.log_event(device_id, ip, reason, detail)
    return jsonify(status="rejected", reason=reason), status


def check_values(reading):
    for name, (low, high) in LIMITS.items():
        value = reading.get(name)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return f"{name} missing or not a number"
        if not low <= value <= high:
            return f"{name}={value} outside {low}..{high}"
    return None


@app.post("/api/v1/telemetry")
def telemetry():
    packet = request.get_json(silent=True)
    try:
        fields = parse_fields(packet)
    except PacketError as exc:
        return reject(400, exc.reason, detail=str(exc))

    device_id, seq = fields["device_id"], fields["seq"]
    keys = DEVICES.get(device_id)
    if keys is None:
        return reject(401, "unknown_device", device_id)

    try:
        reading = verify_and_decrypt(fields, keys["aes_key"],
                                     keys["hmac_key"])
    except AuthenticationFailed as exc:
        return reject(401, exc.reason, device_id, f"seq={seq}")
    except PacketError as exc:
        return reject(400, exc.reason, device_id, str(exc))

    problem = check_values(reading)
    if problem:
        return reject(422, "out_of_range", device_id, problem)

    stored, last_seq = storage.store_if_fresh(device_id, seq, reading)
    if not stored:
        return reject(409, "replay", device_id,
                      f"seq={seq} <= last_seq={last_seq}")

    log.info("ACCEPT device=%s seq=%d temp=%.2fC hum=%.2f%%",
             device_id, seq, reading["temp_c"], reading["humidity"])
    return jsonify(status="accepted", seq=seq), 201


@app.post("/api/v1/telemetry/plain")
def telemetry_plain():
    """INSECURE baseline - exists only for the Wireshark comparison."""
    if not app.config["ALLOW_PLAIN"]:
        return jsonify(status="disabled"), 404
    data = request.get_json(silent=True) or {}
    reading = data.get("reading", {})
    if check_values(reading):
        return jsonify(status="rejected"), 400
    storage.store_plain(str(data.get("device_id", "?"))[:32], reading)
    log.info("PLAIN  device=%s (no security checks!)", data.get("device_id"))
    return jsonify(status="stored-insecurely"), 201


@app.get("/api/v1/readings")
def readings():
    return jsonify(storage.recent_readings(int(request.args.get("limit", 50))))


@app.get("/")
def dashboard():
    return render_template("dashboard.html",
                           readings=storage.recent_readings(15),
                           events=storage.recent_events(10),
                           stats=storage.stats(),
                           devices=sorted(DEVICES))


def main():
    parser = argparse.ArgumentParser(description="Secure sensor data server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--db", default=str(BASE_DIR / "data" / "sensor.db"))
    parser.add_argument("--keys", default=str(BASE_DIR / "devices.json"))
    parser.add_argument("--allow-plain", action="store_true",
                        help="enable the insecure plaintext endpoint (demo only)")
    args = parser.parse_args()

    (BASE_DIR / "data").mkdir(exist_ok=True)
    (BASE_DIR / "logs").mkdir(exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
        handlers=[logging.StreamHandler(),
                  logging.FileHandler(BASE_DIR / "logs" / "server.log")])
    logging.getLogger("werkzeug").setLevel(logging.WARNING)

    DEVICES.update(load_device_keys(args.keys))
    storage.init(args.db)
    app.config["ALLOW_PLAIN"] = args.allow_plain
    log.info("Loaded %d device key(s): %s", len(DEVICES), ", ".join(sorted(DEVICES)))
    if args.allow_plain:
        log.warning("Plaintext endpoint ENABLED - use only for the comparison demo")
    app.run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()
