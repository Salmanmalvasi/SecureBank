/*
  Secure OTP Token - ESP32 firmware (DA1 project)
  Hardware: ESP32 dev board, DS3231 RTC, SSD1306 0.96" OLED (I2C), push button,
            buzzer / status LED.

  Libraries (Arduino IDE > Library Manager):
    - RTClib            (Adafruit)
    - Adafruit SSD1306  (also installs Adafruit GFX)
  mbedtls (HMAC-SHA256) is already part of the ESP32 board package.

  Same algorithm as the Python server (otp.py):
    key     = HKDF-SHA256(MASTER_SECRET, salt = DEVICE_ID, info = "OTP-KEY", 32 bytes)
    counter = unix_time / 30  (8 bytes, big-endian)
    otp     = dynamic truncation of HMAC-SHA256(key, counter) -> 6 digits

  How it talks to the website:
    USB serial (115200): on button press it prints  OTP:123456
                         the web page reads this ("Connect token" button).
                         It also accepts  T<unix_time>  to set the RTC (UTC).
    Wi-Fi (optional):    set USE_WIFI to 1 and the code is POSTed to the server.
*/
#include <Wire.h>
#include <RTClib.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include "mbedtls/md.h"

// ======================= CHANGE THESE IF NEEDED =======================
#define DEVICE_ID   "TOKEN-001"
// Demo secret (same as the server's default). Run provision.py for a real one.
static const uint8_t MASTER_SECRET[32] = {
  0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
  0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00 };

#define PIN_SDA     21      // I2C shared by RTC and OLED
#define PIN_SCL     22
#define PIN_BUTTON  4       // button to GND (internal pull-up used)
#define PIN_BUZZER  5       // active buzzer
#define PIN_LED     2       // status LED (on-board LED on most boards)
#define OLED_ADDR   0x3C

#define USE_WIFI    0       // 1 = also send the code to the server over Wi-Fi
#define WIFI_SSID   "your-wifi"
#define WIFI_PASS   "your-password"
#define SERVER_URL  "http://192.168.1.50:5000/api/push"   // PC running app.py

#define SHOW_MS     20000   // how long the OTP stays on screen after a press
// ======================================================================

#define OTP_STEP    30
#define OTP_DIGITS  6

#if USE_WIFI
#include <WiFi.h>
#include <HTTPClient.h>
#endif

RTC_DS3231 rtc;
Adafruit_SSD1306 oled(128, 64, &Wire, -1);

static unsigned long showUntil = 0;
static char otpText[OTP_DIGITS + 1] = "";
static String serialLine;

// ------------------------------ crypto ------------------------------
static bool hmac256(const uint8_t *key, size_t klen, const uint8_t *msg, size_t mlen,
                    uint8_t out[32]) {
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  return mbedtls_md_hmac(info, key, klen, msg, mlen, out) == 0;
}

// HKDF-SHA256 (RFC 5869), one output block = 32 bytes
static void deriveKey(uint8_t key[32]) {
  uint8_t prk[32];
  hmac256((const uint8_t *)DEVICE_ID, strlen(DEVICE_ID), MASTER_SECRET, 32, prk);  // extract
  const char *info = "OTP-KEY";
  uint8_t t[8];
  memcpy(t, info, 7);
  t[7] = 0x01;
  hmac256(prk, 32, t, 8, key);                                                      // expand
}

static void makeOtp(uint32_t unixTime, char out[OTP_DIGITS + 1]) {
  uint64_t counter = unixTime / OTP_STEP;
  uint8_t msg[8];
  for (int i = 7; i >= 0; i--) { msg[i] = counter & 0xFF; counter >>= 8; }

  uint8_t key[32], mac[32];
  deriveKey(key);
  hmac256(key, 32, msg, 8, mac);

  int off = mac[31] & 0x0F;
  uint32_t code = ((uint32_t)(mac[off] & 0x7F) << 24) | ((uint32_t)mac[off + 1] << 16) |
                  ((uint32_t)mac[off + 2] << 8) | (uint32_t)mac[off + 3];
  snprintf(out, OTP_DIGITS + 1, "%06lu", (unsigned long)(code % 1000000UL));
}

// ------------------------------ helpers ------------------------------
static void beep(int ms) {
  digitalWrite(PIN_BUZZER, HIGH);
  digitalWrite(PIN_LED, HIGH);
  delay(ms);
  digitalWrite(PIN_BUZZER, LOW);
  digitalWrite(PIN_LED, LOW);
}

static void drawIdle(bool clockBad) {
  oled.clearDisplay();
  oled.setTextColor(SSD1306_WHITE);
  oled.setTextSize(1);
  oled.setCursor(0, 0);
  oled.print("SECURE OTP TOKEN");
  oled.setCursor(0, 14);
  oled.print(DEVICE_ID);
  oled.setCursor(0, 40);
  oled.print(clockBad ? "Clock not set!" : "Press button");
  if (clockBad) { oled.setCursor(0, 52); oled.print("Use web: Sync clock"); }
  oled.display();
}

static void drawOtp(uint32_t now) {
  int left = OTP_STEP - (now % OTP_STEP);
  char cur[OTP_DIGITS + 1];
  makeOtp(now, cur);
  oled.clearDisplay();
  oled.setTextColor(SSD1306_WHITE);
  oled.setTextSize(1);
  oled.setCursor(0, 0);
  oled.print("Your one-time code");
  oled.setTextSize(3);
  oled.setCursor(4, 18);
  oled.print(cur);
  oled.setTextSize(1);
  oled.setCursor(0, 50);
  oled.print("expires in ");
  oled.print(left);
  oled.print("s");
  oled.drawRect(0, 60, 128, 4, SSD1306_WHITE);
  oled.fillRect(0, 60, (128 * left) / OTP_STEP, 4, SSD1306_WHITE);
  oled.display();
}

#if USE_WIFI
static void pushToServer(const char *code) {
  if (WiFi.status() != WL_CONNECTED) { Serial.println("PUSH:nowifi"); return; }
  HTTPClient http;
  http.begin(SERVER_URL);
  http.addHeader("Content-Type", "application/json");
  String body = String("{\"device\":\"") + DEVICE_ID + "\",\"otp\":\"" + code + "\"}";
  int rc = http.POST(body);
  Serial.printf("PUSH:%d\n", rc);
  http.end();
}
#endif

static void handleSerial() {
  while (Serial.available()) {
    char c = Serial.read();
    if (c != '\n') { if (c != '\r') serialLine += c; continue; }
    if (serialLine.startsWith("T")) {                    // T<unix time, UTC>
      uint32_t t = (uint32_t)strtoul(serialLine.c_str() + 1, nullptr, 10);
      if (t > 1700000000UL) {
        rtc.adjust(DateTime(t));
        Serial.printf("OK TIME %lu\n", (unsigned long)t);
      } else {
        Serial.println("ERR bad time");
      }
    } else if (serialLine == "ID") {
      Serial.printf("OK ID %s\n", DEVICE_ID);
    } else if (serialLine == "NOW") {
      Serial.printf("OK NOW %lu\n", (unsigned long)rtc.now().unixtime());
    }
    serialLine = "";
  }
}

// -------------------------------- main --------------------------------
void setup() {
  Serial.begin(115200);
  pinMode(PIN_BUTTON, INPUT_PULLUP);
  pinMode(PIN_BUZZER, OUTPUT);
  pinMode(PIN_LED, OUTPUT);
  Wire.begin(PIN_SDA, PIN_SCL);

  if (!oled.begin(SSD1306_SWITCHCAPVCC, OLED_ADDR)) Serial.println("ERR oled");
  if (!rtc.begin()) Serial.println("ERR rtc");

#if USE_WIFI
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  unsigned long t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 10000) delay(250);
#endif
  Serial.println("OK READY");
  drawIdle(rtc.lostPower());
}

void loop() {
  handleSerial();

  if (digitalRead(PIN_BUTTON) == LOW) {
    delay(30);                                   // debounce
    if (digitalRead(PIN_BUTTON) == LOW) {
      uint32_t now = rtc.now().unixtime();
      makeOtp(now, otpText);
      Serial.printf("OTP:%s\n", otpText);        // read by the web page over USB
#if USE_WIFI
      pushToServer(otpText);
#endif
      beep(80);
      showUntil = millis() + SHOW_MS;
      while (digitalRead(PIN_BUTTON) == LOW) delay(10);   // wait for release
    }
  }

  static unsigned long lastDraw = 0;
  if (millis() - lastDraw > 250) {
    lastDraw = millis();
    if (millis() < showUntil) drawOtp(rtc.now().unixtime());
    else drawIdle(rtc.lostPower());
  }
}
