#include <Arduino.h>
#include <Preferences.h>
#include <mbedtls/md.h>
#include <esp_system.h>
#include <cstring>

static constexpr size_t SECRET_LEN = 32;
static constexpr char PROTOCOL[] = "ESP-KEY/0.1";

Preferences prefs;
uint8_t secret[SECRET_LEN];
bool secretReady = false;

static String hexEncode(const uint8_t *buf, size_t len) {
  const char *hex = "0123456789abcdef";
  String out;
  out.reserve(len * 2);
  for (size_t i = 0; i < len; i++) {
    out += hex[buf[i] >> 4];
    out += hex[buf[i] & 0x0f];
  }
  return out;
}

static bool hexDecode(const String &s, uint8_t *out, size_t len) {
  if (s.length() != len * 2) return false;

  auto value = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };

  for (size_t i = 0; i < len; i++) {
    int hi = value(s[2 * i]);
    int lo = value(s[2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return true;
}

static bool loadSecret() {
  std::memset(secret, 0, sizeof(secret));
  if (!prefs.begin("esp-key", false)) return false;

  const bool initialized = prefs.getBool("init", false);
  const size_t storedLen = prefs.getBytesLength("secret");

  if (initialized) {
    if (storedLen != SECRET_LEN ||
        prefs.getBytes("secret", secret, SECRET_LEN) != SECRET_LEN) {
      prefs.end();
      std::memset(secret, 0, sizeof(secret));
      return false;
    }
    prefs.end();
    return true;
  }

  // Migration/recovery path for the original v0.1 firmware: if a valid
  // 32-byte secret already exists, keep it and mark provisioning complete.
  if (storedLen == SECRET_LEN) {
    if (prefs.getBytes("secret", secret, SECRET_LEN) != SECRET_LEN ||
        prefs.putBool("init", true) != 1) {
      prefs.end();
      std::memset(secret, 0, sizeof(secret));
      return false;
    }
    prefs.end();
    return true;
  }

  // A non-empty secret with an unexpected size is treated as corruption.
  // Fail closed instead of silently creating a different device identity.
  if (storedLen != 0) {
    prefs.end();
    return false;
  }

  esp_fill_random(secret, sizeof(secret));
  if (prefs.putBytes("secret", secret, SECRET_LEN) != SECRET_LEN) {
    prefs.end();
    std::memset(secret, 0, sizeof(secret));
    return false;
  }

  uint8_t verify[SECRET_LEN];
  bool writeVerified =
      prefs.getBytes("secret", verify, SECRET_LEN) == SECRET_LEN &&
      std::memcmp(secret, verify, SECRET_LEN) == 0;
  std::memset(verify, 0, sizeof(verify));

  if (!writeVerified || prefs.putBool("init", true) != 1) {
    prefs.end();
    std::memset(secret, 0, sizeof(secret));
    return false;
  }

  prefs.end();
  return true;
}

static void replyHmac(const String &hexChallenge) {
  if (!secretReady) {
    Serial.println("ERR storage-not-ready");
    return;
  }

  uint8_t challenge[SECRET_LEN];
  uint8_t mac[SECRET_LEN];
  if (!hexDecode(hexChallenge, challenge, SECRET_LEN)) {
    Serial.println("ERR bad-challenge");
    return;
  }

  const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (md == nullptr ||
      mbedtls_md_hmac(md, secret, sizeof(secret), challenge, sizeof(challenge), mac) != 0) {
    std::memset(challenge, 0, sizeof(challenge));
    std::memset(mac, 0, sizeof(mac));
    Serial.println("ERR hmac");
    return;
  }

  Serial.print("HMAC ");
  Serial.println(hexEncode(mac, sizeof(mac)));
  std::memset(challenge, 0, sizeof(challenge));
  std::memset(mac, 0, sizeof(mac));
}

static bool isPrintableCommand(const String &line) {
  for (size_t i = 0; i < line.length(); i++) {
    const uint8_t c = static_cast<uint8_t>(line[i]);
    if (c < 0x20 || c > 0x7e) return false;
  }
  return true;
}

void setup() {
  Serial.begin(115200);
  Serial.setTimeout(250);
  delay(500);

  secretReady = loadSecret();
  Serial.print("READY ");
  Serial.print(PROTOCOL);
  Serial.print(" storage=");
  Serial.println(secretReady ? "ok" : "error");
}

void loop() {
  if (!Serial.available()) return;

  String line = Serial.readStringUntil('\n');
  line.trim();
  if (line.length() == 0) return;

  // Ignore terminal control characters instead of reporting them as protocol
  // errors (for example Ctrl+C from a serial monitor).
  if (!isPrintableCommand(line)) return;

  if (line.length() > 80) {
    Serial.println("ERR command-too-long");
    return;
  }

  if (line == "PING") {
    Serial.print("OK ");
    Serial.println(PROTOCOL);
  } else if (line == "STATUS") {
    Serial.print("STATUS storage=");
    Serial.println(secretReady ? "ok" : "error");
  } else if (line == "ID") {
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    Serial.print("ID ");
    Serial.println(hexEncode(mac, sizeof(mac)));
    std::memset(mac, 0, sizeof(mac));
  } else if (line.startsWith("HMAC ")) {
    replyHmac(line.substring(5));
  } else {
    Serial.println("ERR unknown-command");
  }
}
