# SecureBank - OTP login demo (DA1 project)

Net-banking demo protected by the ESP32 OTP token (HKDF + HMAC-SHA256, 30 s codes).

## 1. Run the website
    pip install -r requirements.txt
    python app.py            # http://127.0.0.1:5000

Accounts (password `bank123`): 1001234567 (Salman, TOKEN-001), 2002345678, 3003456789.
Use TOKEN-001 with the real hardware. For the other two: `python device_sim.py TOKEN-002`.

## 2. Flash the token
1. Arduino IDE > Library Manager: install **RTClib** and **Adafruit SSD1306** (plus Adafruit GFX).
2. Open `firmware/otp_token/otp_token.ino`, board = your ESP32 Dev Module.
3. Check the pins at the top (defaults: SDA 21, SCL 22, button GPIO 4, buzzer GPIO 5, LED GPIO 2, OLED 0x3C).
4. Upload. Close the Serial Monitor afterwards (the browser needs the port).

## 3. Connect the token to the website
**USB (easiest, Chrome or Edge):** on the OTP page click *Connect token (USB)*, pick the ESP32
port, press the token button. The code is read from the serial line `OTP:123456` and the form
submits itself. First time only, click *Sync token clock* so the DS3231 holds UTC time
(the server compares against UTC; a wrong RTC is the usual reason codes are rejected).

**Wi-Fi (optional):** in the .ino set `USE_WIFI 1`, your Wi-Fi name/password and `SERVER_URL`
(your PC's IP, port 5000). Press the button while the OTP page is open and the page logs you in
by itself. Allow port 5000 in the PC firewall.

## Algorithm (firmware = server)
1. key = HKDF-SHA256(master, salt = device_id, info = "OTP-KEY", 32 bytes)
2. counter = floor(unix_time / 30), 8 bytes big-endian
3. mac = HMAC-SHA256(key, counter); offset = mac[31] & 0x0F
4. code = (4 bytes at offset, top bit cleared) mod 10^6, zero-padded

## Real master key (provisioning step)
    python provision.py TOKEN-001
Prints the `MASTER_SECRET` line to paste into the .ino; the database is updated to match.

## Website features
Two-step login, dashboard, transfers (>= Rs 10,000 needs a fresh OTP), statement with filter/search/CSV,
security page with token info and activity log, CSRF tokens, 5-minute sessions, 3-strikes lockout,
replay protection (each code works once), +/-1 step clock-drift tolerance, `/api/push` for the device.

Demo only: for a real bank use HTTPS, a production server and secure key storage (e.g. the planned EEPROM/secure element).
