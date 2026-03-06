/**
 * Émetteur FSK avec DHT22
 * Transmission: Température et Humidité
 */

#include <DHT.h>

#define DHTPIN 4
#define DHTTYPE DHT22
DHT dht(DHTPIN, DHTTYPE);

#define PIN_LED 25
#define LEDC_RESOLUTION 8
#define FREQ_BIT0 1000  // 1 kHz pour bit 0
#define FREQ_BIT1 2000  // 2 kHz pour bit 1
#define BIT_DURATION 5  // 5ms pour 200 bits/s

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("\n=== ÉMETTEUR FSK LiFi + DHT22 ===");
  
  // Attacher le pin au LEDC avec une fréquence initiale
  bool ok = ledcAttach(PIN_LED, FREQ_BIT0, LEDC_RESOLUTION);
  if(ok) Serial.println("LED FSK: ✅");
  else Serial.println("LED FSK: ❌");
  
  // Initialiser DHT22
  dht.begin();
  Serial.println("DHT22: ✅");
  
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
  
  // Préparer les bytes à envoyer
  byte temp_high = highByte(temp_int);
  byte temp_low = lowByte(temp_int);
  byte hum_high = highByte(hum_int);
  byte hum_low = lowByte(hum_int);
  
  // Calculer checksum
  byte checksum = (temp_high + temp_low + hum_high + hum_low) & 0xFF;
  
  Serial.println("\n========================================");
  Serial.println(">>> TRANSMISSION");
  Serial.print("Temperature: ");
  Serial.print(temperature, 1);
  Serial.println(" C");
  Serial.print("Humidite: ");
  Serial.print(humidite, 1);
  Serial.println(" %");
  Serial.println("========================================");
  
  // PRÉAMBULE: 10101010 (8 bits)
  Serial.println("1. Envoi PREAMBULE: 10101010");
  for(int i=0; i<4; i++) {
    sendBit(1);
    sendBit(0);
  }
  
  // DONNÉES: 4 bytes (temp_high, temp_low, hum_high, hum_low)
  Serial.println("2. Envoi DONNEES (4 bytes)");
  sendByte(temp_high);
  sendByte(temp_low);
  sendByte(hum_high);
  sendByte(hum_low);
  
  // CHECKSUM: 1 byte
  Serial.println("3. Envoi CHECKSUM");
  sendByte(checksum);
  
  // FIN: 00000000 (8 bits)
  Serial.println("4. Envoi FIN: 00000000");
  for(int i=0; i<8; i++) {
    sendBit(0);
  }
  
  Serial.println(">>> TRANSMISSION TERMINEE\n");
  
  delay(3000);  // Pause plus longue entre transmissions
}