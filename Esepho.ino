/**
 * Émetteur FSK avec DHT22 + Chiffrement AES-128
 * Transmission: Température et Humidité chiffrées
 */

#include <DHT.h>
#include "mbedtls/aes.h"

#define DHTPIN 4
#define DHTTYPE DHT22
DHT dht(DHTPIN, DHTTYPE);

// Clé AES-128 (16 bytes) - À partager avec le récepteur
unsigned char aes_key[16] = {
  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
  0xab, 0xf7, 0x97, 0x46, 0x09, 0xcf, 0x4f, 0x3c
};

mbedtls_aes_context aes;

#define PIN_LED 25
#define LEDC_RESOLUTION 8
#define FREQ_BIT0 1000  // 1 kHz pour bit 0
#define FREQ_BIT1 2000  // 2 kHz pour bit 1
#define BIT_DURATION 5  // 5ms pour 200 bits/s

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("\n=== ÉMETTEUR FSK LiFi + DHT22 + AES-128 ===");
  
  // Attacher le pin au LEDC avec une fréquence initiale
  bool ok = ledcAttach(PIN_LED, FREQ_BIT0, LEDC_RESOLUTION);
  if(ok) Serial.println("LED FSK: ✅");
  else Serial.println("LED FSK: ❌");
  
  // Initialiser DHT22
  dht.begin();
  Serial.println("DHT22: ✅");
  
  // Initialiser AES
  mbedtls_aes_init(&aes);
  if(mbedtls_aes_setkey_enc(&aes, aes_key, 128) == 0) {
    Serial.println("AES-128: ✅");
  } else {
    Serial.println("AES-128: ❌");
  }
  
  delay(2000);
}

// Fonction pour envoyer un bit
void sendBit(bool bit) {
  if(bit) {
    ledcWriteTone(PIN_LED, FREQ_BIT1);  // bit = 1 → 500 Hz
  } else {
    ledcWriteTone(PIN_LED, FREQ_BIT0);  // bit = 0 → 400 Hz
  }
  delay(BIT_DURATION);

}

// Fonction pour envoyer un byte
void sendByte(byte data) {
  for (int i = 7; i >= 0; i--) {
    bool bit = (data >> i) & 0x01;
    sendBit(bit);
  }
}

void loop() {
  // Lire DHT22
  float temperature = dht.readTemperature();
  // float temperature = 10;
  float humidite = dht.readHumidity();
  // float humidite = 10;
  
  if (isnan(temperature) || isnan(humidite)) {
    Serial.println("Erreur lecture DHT22!");
    delay(2000);
    return;
  }
  
  // Convertir en entiers (x10 pour garder 1 décimale)
  int temp_int = (int)(temperature * 10);
  int hum_int = (int)(humidite * 10);
  
  // Préparer les bytes à envoyer (données en clair)
  byte temp_high = highByte(temp_int);
  byte temp_low = lowByte(temp_int);
  byte hum_high = highByte(hum_int);
  byte hum_low = lowByte(hum_int);
  
  // Préparer le bloc de 16 bytes pour AES (padding avec des zéros)
  unsigned char plaintext[16] = {0};
  plaintext[0] = temp_high;
  plaintext[1] = temp_low;
  plaintext[2] = hum_high;
  plaintext[3] = hum_low;
  
  // Calculer checksum des données en clair
  byte checksum = (temp_high + temp_low + hum_high + hum_low) & 0xFF;
  plaintext[4] = checksum;
  
  // Chiffrer avec AES-128
  unsigned char ciphertext[16];
  mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, plaintext, ciphertext);
  
  Serial.println("\n========================================");
  Serial.println(">>> TRANSMISSION CHIFFREE");
  Serial.print("Temperature: ");
  Serial.print(temperature, 1);
  Serial.println(" C");
  Serial.print("Humidite: ");
  Serial.print(humidite, 1);
  Serial.println(" %");
  Serial.println("========================================");
  
  // Afficher les données en clair
  Serial.println("\nDonnees EN CLAIR (5 bytes):");
  Serial.print("  [0] Temp High:  0x");
  Serial.print(plaintext[0], HEX);
  Serial.print(" (");
  Serial.print(plaintext[0]);
  Serial.println(")");
  Serial.print("  [1] Temp Low:   0x");
  Serial.print(plaintext[1], HEX);
  Serial.print(" (");
  Serial.print(plaintext[1]);
  Serial.println(")");
  Serial.print("  [2] Hum High:   0x");
  Serial.print(plaintext[2], HEX);
  Serial.print(" (");
  Serial.print(plaintext[2]);
  Serial.println(")");
  Serial.print("  [3] Hum Low:    0x");
  Serial.print(plaintext[3], HEX);
  Serial.print(" (");
  Serial.print(plaintext[3]);
  Serial.println(")");
  Serial.print("  [4] Checksum:   0x");
  Serial.print(plaintext[4], HEX);
  Serial.print(" (");
  Serial.print(plaintext[4]);
  Serial.println(")");
  
  // Afficher les données chiffrées
  Serial.println("\nDonnees CHIFFREES AES-128 (16 bytes):");
  for(int i=0; i<16; i++) {
    Serial.print("  [");
    Serial.print(i);
    Serial.print("] 0x");
    if(ciphertext[i] < 16) Serial.print("0");
    Serial.print(ciphertext[i], HEX);
    Serial.print(" (");
    Serial.print(ciphertext[i]);
    Serial.println(")");
  }
  Serial.println();
  
  // PRÉAMBULE: 10101010 (8 bits)
  Serial.println("1. Envoi PREAMBULE: 10101010");
  for(int i=0; i<4; i++) {
    sendBit(1);
    sendBit(0);
  }
  
  // DONNÉES CHIFFRÉES: 16 bytes (bloc AES complet)
  Serial.println("2. Envoi DONNEES CHIFFREES (16 bytes AES)");
  for(int i=0; i<16; i++) {
    sendByte(ciphertext[i]);
  }
  
  // FIN: 00000000 (8 bits)
  Serial.println("4. Envoi FIN: 00000000");
  for(int i=0; i<8; i++) {
    sendBit(0);
  }
  
  Serial.println(">>> TRANSMISSION TERMINEE\n");
  
  delay(3000);  // Pause plus longue entre transmissions
}