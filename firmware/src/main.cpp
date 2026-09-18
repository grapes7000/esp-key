#include <Arduino.h>
#include <Preferences.h>
#include <mbedtls/md.h>
#include <esp_system.h>

Preferences prefs;
uint8_t secret[32];

static String hexEncode(const uint8_t *buf, size_t len) {
  const char *hex = "0123456789abcdef";
  String out; out.reserve(len * 2);
  for (size_t i=0;i<len;i++){ out += hex[buf[i]>>4]; out += hex[buf[i]&15]; }
  return out;
}
static bool hexDecode(const String &s, uint8_t *out, size_t len) {
  if (s.length()!=len*2) return false;
  for(size_t i=0;i<len;i++){
    char a=s[2*i], b=s[2*i+1];
    auto v=[](char c)->int { if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1; };
    int x=v(a),y=v(b); if(x<0||y<0)return false; out[i]=(x<<4)|y;
  } return true;
}
static void loadSecret(){
  prefs.begin("esp-key", false);
  if(prefs.getBytesLength("secret")!=32){
    esp_fill_random(secret, sizeof(secret));
    prefs.putBytes("secret", secret, sizeof(secret));
  } else prefs.getBytes("secret", secret, sizeof(secret));
}
static void replyHmac(const String &hexChallenge){
  uint8_t challenge[32], mac[32];
  if(!hexDecode(hexChallenge,challenge,32)){ Serial.println("ERR bad-challenge"); return; }
  const mbedtls_md_info_t *md=mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if(mbedtls_md_hmac(md,secret,sizeof(secret),challenge,sizeof(challenge),mac)!=0){ Serial.println("ERR hmac"); return; }
  Serial.print("HMAC "); Serial.println(hexEncode(mac,sizeof(mac)));
}
void setup(){ Serial.begin(115200); delay(500); loadSecret(); Serial.println("READY ESP-KEY/0.1"); }
void loop(){
  if(!Serial.available()) return;
  String line=Serial.readStringUntil('\n'); line.trim();
  if(line=="PING") Serial.println("OK ESP-KEY/0.1");
  else if(line=="ID"){ uint8_t mac[6]; esp_read_mac(mac,ESP_MAC_WIFI_STA); Serial.print("ID "); Serial.println(hexEncode(mac,6)); }
  else if(line.startsWith("HMAC ")) replyHmac(line.substring(5));
  else Serial.println("ERR unknown-command");
}
