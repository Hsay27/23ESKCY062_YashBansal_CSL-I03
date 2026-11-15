/*
 * firmware_crypto_test.cpp - runs the ESP32's secure_packet.h on a PC.
 *
 * Proves that the C/mbedTLS code on the ESP32 and the Python server agree
 * byte for byte, without needing the board. Linux / WSL:
 *
 *   sudo apt install libmbedtls-dev
 *   g++ firmware_crypto_test.cpp -I ../../firmware/esp32_secure_sensor -lmbedcrypto -o fwtest
 *   ./fwtest 7 > packet.json
 *   python ../verify_packet.py packet.json
 */
#include <stdio.h>
#include <stdlib.h>
#include "secrets.h"
#include "secure_packet.h"

int main(int argc, char **argv) {
  uint32_t seq = argc > 1 ? (uint32_t)strtoul(argv[1], NULL, 10) : 1;

  uint8_t iv[SP_IV_LEN];                       // PC stand-in for esp_fill_random
  FILE *f = fopen("/dev/urandom", "rb");
  if (!f || fread(iv, 1, sizeof(iv), f) != sizeof(iv)) return 1;
  fclose(f);

  const char *plain = "{\"temp_c\":27.40,\"humidity\":51.20,\"ts\":1762337000}";
  char out[SP_MAX_PACKET];
  int n = sp_build_packet(DEVICE_ID, seq, plain, AES_KEY, HMAC_KEY, sizeof(HMAC_KEY),
                          iv, out, sizeof(out));
  if (n < 0) { fprintf(stderr, "packet build failed\n"); return 1; }
  puts(out);
  return 0;
}
