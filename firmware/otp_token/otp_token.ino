/*
  Secure OTP Token - ESP32 firmware
  Hardware: ESP32, DS3231 RTC, SSD1306 OLED

  USB commands:
    T<unix_time> - Set RTC time
    ID           - Return device ID
    NOW          - Return current RTC time
    GETOTP       - Return the current OTP over USB

  OTP algorithm (unchanged):
    HKDF-SHA256
    HMAC-SHA256
    6-digit TOTP with 30-second time steps
*/

#include <Wire.h>
#include <RTClib.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include "mbedtls/md.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define DEVICE_ID "TOKEN-001"

static const uint8_t MASTER_SECRET[32] = {
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
  0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00
};

#define PIN_SDA 21
#define PIN_SCL 22
#define OLED_ADDR 0x3C

#define OTP_STEP 30
#define OTP_DIGITS 6

RTC_DS3231 rtc;
Adafruit_SSD1306 oled(128, 64, &Wire, -1);

static char serialLine[65];
static size_t serialLength = 0;
static bool clockReady = false;

static bool hmac256(
  const uint8_t *key,
  size_t klen,
  const uint8_t *msg,
  size_t mlen,
  uint8_t out[32]
) {
  const mbedtls_md_info_t *info =
    mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

  if (info == nullptr) return false;

  return mbedtls_md_hmac(info, key, klen, msg, mlen, out) == 0;
}

static bool deriveKey(uint8_t key[32]) {
  uint8_t prk[32];

  if (!hmac256(
        (const uint8_t *)DEVICE_ID,
        strlen(DEVICE_ID),
        MASTER_SECRET,
        sizeof(MASTER_SECRET),
        prk)) {
    return false;
  }

  const char *info = "OTP-KEY";
  uint8_t t[8];

  memcpy(t, info, 7);
  t[7] = 0x01;

  return hmac256(prk, sizeof(prk), t, sizeof(t), key);
}

static bool makeOtp(uint32_t unixTime, char out[OTP_DIGITS + 1]) {
  uint64_t counter = unixTime / OTP_STEP;
  uint8_t msg[8];

  for (int i = 7; i >= 0; i--) {
    msg[i] = counter & 0xFF;
    counter >>= 8;
  }

  uint8_t key[32];
  uint8_t mac[32];

  if (!deriveKey(key) || !hmac256(key, sizeof(key), msg, sizeof(msg), mac)) {
    strcpy(out, "------");
    return false;
  }

  int off = mac[31] & 0x0F;

  uint32_t code =
    ((uint32_t)(mac[off] & 0x7F) << 24) |
    ((uint32_t)mac[off + 1] << 16) |
    ((uint32_t)mac[off + 2] << 8) |
    (uint32_t)mac[off + 3];

  snprintf(out, OTP_DIGITS + 1, "%06lu",
           (unsigned long)(code % 1000000UL));
  return true;
}

static void drawClockError() {
  oled.clearDisplay();
  oled.setTextColor(SSD1306_WHITE);
  oled.setTextSize(1);
  oled.setCursor(0, 0);
  oled.println("SECUREBANK TOKEN");
  oled.setCursor(0, 18);
  oled.println(DEVICE_ID);
  oled.setCursor(0, 36);
  oled.println("Clock not set!");
  oled.setCursor(0, 50);
  oled.println("Sync clock from site");
  oled.display();
}

static void drawOtp(uint32_t now) {
  char cur[OTP_DIGITS + 1];

  if (!makeOtp(now, cur)) {
    drawClockError();
    return;
  }

  int left = OTP_STEP - (now % OTP_STEP);
  DateTime dt(now);

  char timeText[9];
  snprintf(timeText, sizeof(timeText), "%02d:%02d:%02d",
           dt.hour(), dt.minute(), dt.second());

  oled.clearDisplay();
  oled.setTextColor(SSD1306_WHITE);

  oled.setTextSize(1);
  oled.setCursor(0, 0);
  oled.print("SECUREBANK OTP");

  oled.setCursor(0, 10);
  oled.print(DEVICE_ID);

  oled.setTextSize(3);
  oled.setCursor(8, 22);
  oled.print(cur);

  oled.setTextSize(1);
  oled.setCursor(0, 49);
  oled.print("Refreshes in ");
  oled.print(left);
  oled.print("s");

  oled.setCursor(0, 58);
  oled.print(timeText);

  oled.display();
}

static void handleCommand(const char *line) {
  if (line[0] == 'T' && line[1] != '\0') {
    uint32_t t = (uint32_t)strtoul(line + 1, nullptr, 10);

    if (t > 1700000000UL) {
      rtc.adjust(DateTime(t));
      clockReady = true;
      Serial.printf("OK TIME %lu\n", (unsigned long)t);
    } else {
      Serial.println("ERR bad time");
    }
  } else if (strcmp(line, "ID") == 0) {
    Serial.printf("OK ID %s\n", DEVICE_ID);
  } else if (strcmp(line, "NOW") == 0) {
    Serial.printf("OK NOW %lu\n", (unsigned long)rtc.now().unixtime());
  } else if (strcmp(line, "GETOTP") == 0) {
    uint32_t now = rtc.now().unixtime();

    if (now < 1700000000UL) {
      Serial.println("ERR clock not set");
    } else {
      char currentOtp[OTP_DIGITS + 1];
      if (makeOtp(now, currentOtp)) {
        Serial.printf("OTP:%s\n", currentOtp);
      } else {
        Serial.println("ERR OTP generation failed");
      }
    }
  }
}

static void handleSerial() {
  while (Serial.available() > 0) {
    char c = (char)Serial.read();

    if (c == '\n') {
      serialLine[serialLength] = '\0';
      if (serialLength > 0) handleCommand(serialLine);
      serialLength = 0;
    } else if (c != '\r') {
      if (serialLength < sizeof(serialLine) - 1) {
        serialLine[serialLength++] = c;
      } else {
        serialLength = 0;
      }
    }
  }
}

void setup() {
  Serial.begin(115200);
  Wire.begin(PIN_SDA, PIN_SCL);

  if (!oled.begin(SSD1306_SWITCHCAPVCC, OLED_ADDR)) {
    Serial.println("ERR oled");
    while (true) delay(1000);
  }

  if (!rtc.begin()) {
    Serial.println("ERR rtc");
    drawClockError();
    while (true) delay(1000);
  }

  clockReady = !rtc.lostPower();
  Serial.println("OK READY");
}

void loop() {
  handleSerial();

  DateTime current = rtc.now();
  uint32_t now = current.unixtime();

  if (now < 1700000000UL) {
    clockReady = false;
  }

  static uint32_t lastDisplayedSecond = 0;
  if (now != lastDisplayedSecond) {
    lastDisplayedSecond = now;

    if (clockReady || now >= 1700000000UL) {
      drawOtp(now);
    } else {
      drawClockError();
    }
  }
}
