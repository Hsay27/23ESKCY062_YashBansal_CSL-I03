"""
benchmark.py - Measures the cost of security: message size and processing
time of plaintext vs AES + HMAC packets. Does not need the server running.

Usage:  python tools/benchmark.py              (measure + graphs)
        python tools/benchmark.py --plot-only  (redraw graphs from CSV)
Output: results/benchmark.csv, results/size_overhead.png, results/time_cost.png
"""

import csv
import json
import os
import statistics
import sys
import time
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from securepacket import build_packet, parse_fields, verify_and_decrypt  # noqa: E402

N = 2000
AES_KEY, HMAC_KEY = os.urandom(16), os.urandom(32)


def reading_with(n_fields):
    """1 field = temp only ... up to several extra sensor channels."""
    names = ["temp_c", "humidity", "pressure", "light", "co2", "voltage", "rssi", "pm25"]
    r = {names[i]: round(20 + i * 3.17, 2) for i in range(n_fields)}
    r["ts"] = 1762337000
    return r


def timed(fn, n=N):
    samples = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1e6)
    return statistics.median(samples)


def plot(rows, out):
    labels = [str(r["fields"]) for r in rows]
    x = list(range(len(rows)))
    plt.figure(figsize=(6.4, 3.6))
    plt.plot(x, [r["plain_bytes"] for r in rows], "o-", label="Plaintext JSON")
    plt.plot(x, [r["secure_bytes"] for r in rows], "s-", label="AES + HMAC packet")
    plt.xticks(x, labels)
    plt.xlabel("Number of sensor values in one message")
    plt.ylabel("HTTP body size (bytes)")
    plt.title("Message size: plaintext vs secure packet")
    plt.grid(alpha=.3); plt.legend(); plt.tight_layout()
    plt.savefig(out / "size_overhead.png", dpi=200); plt.close()

    plt.figure(figsize=(6.4, 3.6))
    w = 0.38
    plt.bar([i - w / 2 for i in x], [r["encrypt_sign_us"] for r in rows], w,
            label="Encrypt + sign (sender)")
    plt.bar([i + w / 2 for i in x], [r["verify_decrypt_us"] for r in rows], w,
            label="Verify + decrypt (server)")
    plt.xticks(x, labels)
    plt.xlabel("Number of sensor values in one message")
    plt.ylabel("Median time (microseconds)")
    plt.title(f"Processing time per message (Python, median of {N})")
    plt.grid(alpha=.3, axis="y"); plt.legend(loc="lower right"); plt.tight_layout()
    plt.savefig(out / "time_cost.png", dpi=200); plt.close()


def main():
    out = ROOT / "results"; out.mkdir(exist_ok=True)
    if "--plot-only" in sys.argv:           # redraw graphs from saved CSV
        with open(out / "benchmark.csv") as fh:
            rows = [{k: float(v) for k, v in r.items()} for r in csv.DictReader(fh)]
        for r in rows:
            r["fields"] = int(r["fields"])
        plot(rows, out)
        print(f"Graphs redrawn in {out}")
        return
    rows = []
    for n_fields in (1, 2, 4, 6, 8):
        reading = reading_with(n_fields)
        plain_body = json.dumps({"device_id": "ESP32-01", "reading": reading})
        packet = build_packet("ESP32-01", 1, reading, AES_KEY, HMAC_KEY)
        secure_body = json.dumps(packet)
        fields = parse_fields(packet)
        t_build = timed(lambda: build_packet("ESP32-01", 1, reading, AES_KEY, HMAC_KEY))
        t_verify = timed(lambda: verify_and_decrypt(fields, AES_KEY, HMAC_KEY))
        t_plain = timed(lambda: json.loads(plain_body))
        rows.append({"fields": n_fields, "plain_bytes": len(plain_body),
                     "secure_bytes": len(secure_body),
                     "overhead_pct": round(100 * (len(secure_body) / len(plain_body) - 1), 1),
                     "encrypt_sign_us": round(t_build, 1),
                     "verify_decrypt_us": round(t_verify, 1),
                     "plain_parse_us": round(t_plain, 1)})

    with open(out / "benchmark.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=rows[0].keys())
        w.writeheader(); w.writerows(rows)

    print(f"{'fields':>6} {'plain B':>8} {'secure B':>9} {'overhead':>9} "
          f"{'enc+sign us':>12} {'verify+dec us':>14}")
    for r in rows:
        print(f"{r['fields']:>6} {r['plain_bytes']:>8} {r['secure_bytes']:>9} "
              f"{r['overhead_pct']:>8}% {r['encrypt_sign_us']:>12} {r['verify_decrypt_us']:>14}")

    plot(rows, out)
    print(f"\nSaved results to {out}")


if __name__ == "__main__":
    main()
