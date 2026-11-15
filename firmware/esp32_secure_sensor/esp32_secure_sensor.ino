/*
 * Secure Sensor Data Transmission (ESP32 -> Server)       Project: CSL-I03
 * Yash Bansal (23ESKCY062) - Cyber Security Lab (7CS4-22), SKIT Jaipur
 *
 * Every SEND_INTERVAL_MS the ESP32:
 *   1. reads temperature + humidity from a DHT22
 *   2. builds  {"temp_c":..,"humidity":..,"ts":..}
 *   3. increments and saves a sequence counter (replay protection)
 *   4. encrypts the reading with AES-128-CBC and a fresh random IV
 *   5. signs device_id|seq|iv|ct with HMAC-SHA256
 *   6. POSTs the JSON packet to the server over HTTP
 *
 * Board     : ESP32 Dev Module (Arduino-ESP32 core 2.x or 3.x)
 * Libraries : "DHT sensor library" + "Adafruit Unified Sensor" (Adafruit)
 * Wiring    : DHT22 VCC -> 3V3, DATA -> GPIO4 (10k pull-up to 3V3), GND -> GND
 * No sensor?: set USE_FAKE_SENSOR to 1
 */

#include <WiFi.h>
#include <HTTPClient.h>
#include <Preferences.h>
#include <time.h>
#include <esp_system.h>
#if __has_include(<esp_random.h>)
#include <esp_random.h>
#endif

#include "secrets.h"
#include "secure_packet.h"

#define USE_FAKE_SENSOR   0        // 1 = generate values, no DHT22 needed
#define DHT_PIN           4
#define DHT_TYPE          DHT22
#define SEND_INTERVAL_MS  10000

#if !USE_FAKE_SENSOR
#include <DHT.h>
DHT dht(DHT_PIN, DHT_TYPE);
#endif

Preferences prefs;          // non-volatile storage (survives reboot)
uint32_t seqCounter = 0;

// ---------------------------------------------------------------- Wi-Fi --
void connectWiFi() {
  Serial.printf("[WIFI] Connecting to %s", WIFI_SSID);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.printf("\n[WIFI] Connected, IP = %s\n", WiFi.localIP().toString().c_str());
}

// Real time from NTP (IST = UTC+5:30). Used only as a timestamp in the data.
void syncTime() {
  configTime(19800, 0, "pool.ntp.org", "time.google.com");
  Serial.print("[NTP ] Syncing time");
  for (int i = 0; i < 20 && time(nullptr) < 1700000000; i++) {
    delay(500);
    Serial.print(".");
  }
  Serial.printf("\n[NTP ] Epoch = %lu\n", (unsigned long)time(nullptr));
}

// --------------------------------------------------------------- Sensor --
bool readSensor(float &temp, float &hum) {
#if USE_FAKE_SENSOR
  static float t = 27.0, h = 50.0;
  t += (random(-30, 31)) / 100.0;
  h += (random(-100, 101)) / 100.0;
  temp = t;
  hum = constrain(h, 20, 90);
  return true;
#else
  temp = dht.readTemperature();
  hum = dht.readHumidity();
  return !(isnan(temp) || isnan(hum));
#endif
}

// ---------------------------------------------------------------- Setup --
void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println("\n=== Secure Sensor Node (AES-128-CBC + HMAC-SHA256) ===");
#if !USE_FAKE_SENSOR
  dht.begin();
#endif
  prefs.begin("secsensor", false);
  seqCounter = prefs.getUInt("seq", 0);       // continue after a reboot
  Serial.printf("[INIT] Device %s, last seq = %lu\n", DEVICE_ID,
                (unsigned long)seqCounter);
  connectWiFi();                              // Wi-Fi must be ON before using
  syncTime();                                 // the hardware RNG for IVs
}

// ----------------------------------------------------------------- Loop --
void loop() {
  if (WiFi.status() != WL_CONNECTED) connectWiFi();

  float temp, hum;
  if (!readSensor(temp, hum)) {
    Serial.println("[SENS] Read failed, retrying in 2 s");
    delay(2000);
    return;
  }

  // 1. plaintext reading
  char plain[SP_MAX_PLAIN];
  snprintf(plain, sizeof(plain),
           "{\"temp_c\":%.2f,\"humidity\":%.2f,\"ts\":%lu}",
           temp, hum, (unsigned long)time(nullptr));

  // 2. new sequence number, saved BEFORE sending (never reused)
  seqCounter++;
  prefs.putUInt("seq", seqCounter);

  // 3. fresh random IV from the ESP32 hardware random number generator
  uint8_t iv[SP_IV_LEN];
  esp_fill_random(iv, sizeof(iv));

  // 4. encrypt + sign
  static char packet[SP_MAX_PACKET];
  unsigned long t0 = micros();
  int len = sp_build_packet(DEVICE_ID, seqCounter, plain, AES_KEY,
                            HMAC_KEY, sizeof(HMAC_KEY), iv,
                            packet, sizeof(packet));
  unsigned long cryptoUs = micros() - t0;
  if (len < 0) {
    Serial.println("[CRYP] Packet build failed");
    delay(SEND_INTERVAL_MS);
    return;
  }

  Serial.printf("\n[DATA] seq=%lu plain=%s\n",
                (unsigned long)seqCounter, plain);
  Serial.printf("[CRYP] AES+HMAC took %lu us, packet %d bytes\n",
                cryptoUs, len);
  Serial.printf("[SEND] %s\n", packet);

  // 5. send
  HTTPClient http;
  http.begin(SERVER_URL);
  http.addHeader("Content-Type", "application/json");
  int code = http.POST((uint8_t *)packet, len);
  if (code > 0) {
    Serial.printf("[HTTP] %d %s\n", code, http.getString().c_str());
  } else {
    Serial.printf("[HTTP] Error: %s\n", http.errorToString(code).c_str());
  }
  http.end();
  delay(SEND_INTERVAL_MS);
}
