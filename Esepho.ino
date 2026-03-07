/**
 * Émetteur FSK avec DHT22 + Chiffrement AES-128 + Code Correcteur Hamming(7,4)
 * Transmission: Température et Humidité chiffrées + protégées par ECC
 *
 * Hamming(7,4) : 4 bits de données → 7 bits transmis (3 bits de parité)
 *   Capacité : correction automatique de 1 bit erroné, détection de 2 bits
 *
 * Structure d'un mot Hamming(7,4) :
 *   Position :  7  6  5  4  3  2  1
 *   Contenu  :  d4 d3 d2 p3 d1 p2 p1
 *   p1 = d1 XOR d2 XOR d4
 *   p2 = d1 XOR d3 XOR d4
 *   p3 = d2 XOR d3 XOR d4
 *
 * Par byte AES → 2 nibbles → 2 mots Hamming(7,4) → 14 bits transmis
 * Trame : PRÉAMBULE(8) + [16 bytes × 14 bits Hamming](224) + FIN(8) = 240 bits
 **/

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
#define BIT_DURATION 10  // 10ms → 100 bits/s (BER réduit par meilleure intégration Goertzel)

// ============================================================
//   CODE CORRECTEUR D'ERREUR — HAMMING(7,4)
// ============================================================
/**
 * Encode un nibble (4 bits) en un mot Hamming de 7 bits.
 * @param nibble  4 bits de données (bits 3..0 utilisés, les 4 bits hauts ignorés)
 * @return        7 bits encodés dans les bits 6..0 d'un byte
 *
 * Positions (numérotées 1..7, bit poids fort = position 7) :
 *   pos 1 = p1, pos 2 = p2, pos 3 = d1, pos 4 = p3,
 *   pos 5 = d2, pos 6 = d3, pos 7 = d4
 */
byte hammingEncode(byte nibble) {
  // Extraire les 4 bits de données
  byte d1 = (nibble >> 0) & 1;
  byte d2 = (nibble >> 1) & 1;
  byte d3 = (nibble >> 2) & 1;
  byte d4 = (nibble >> 3) & 1;

  // Calculer les 3 bits de parité (parité paire)
  byte p1 = d1 ^ d2 ^ d4;        // couvre positions 1,3,5,7
  byte p2 = d1 ^ d3 ^ d4;        // couvre positions 2,3,6,7
  byte p3 = d2 ^ d3 ^ d4;        // couvre positions 4,5,6,7

  // Assembler le mot de 7 bits : [d4 d3 d2 p3 d1 p2 p1] (bit6..bit0)
  byte word = (d4 << 6) | (d3 << 5) | (d2 << 4) | (p3 << 3)
            | (d1 << 2) | (p2 << 1) | (p1 << 0);
  return word;
}

// ============================================================
//   ENVOI D'UN BIT ET D'UN BYTE FSK
// ============================================================
// Fonction pour envoyer un bit
void sendBit(bool bit) {
  if (bit) {
    ledcWriteTone(PIN_LED, FREQ_BIT1);  // bit = 1 → 2 kHz
  } else {
    ledcWriteTone(PIN_LED, FREQ_BIT0);  // bit = 0 → 1 kHz
  }
  delay(BIT_DURATION);
}

// Envoyer un byte brut (8 bits, MSB en premier)
void sendByte(byte data) {
  for (int i = 7; i >= 0; i--) {
    sendBit((data >> i) & 0x01);
  }
}

/**
 * Encoder et envoyer un byte AES via Hamming(7,4).
 * Le byte est découpé en 2 nibbles ; chaque nibble donne 7 bits → 14 bits au total.
 * Ordre : nibble haut (bits 7..4) en premier, nibble bas (bits 3..0) ensuite.
 */
void sendByteHamming(byte data) {
  byte nibbleHigh = (data >> 4) & 0x0F;  // 4 bits hauts
  byte nibbleLow  =  data       & 0x0F;  // 4 bits bas

  byte wordHigh = hammingEncode(nibbleHigh);
  byte wordLow  = hammingEncode(nibbleLow);

  // Émettre les 7 bits de chaque mot (MSB en premier, bits 6..0)
  for (int i = 6; i >= 0; i--) {
    sendBit((wordHigh >> i) & 0x01);
  }
  for (int i = 6; i >= 0; i--) {
    sendBit((wordLow >> i) & 0x01);
  }
}

// ============================================================
//   SETUP
// ============================================================
void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("\n=== ÉMETTEUR FSK LiFi + DHT22 + AES-128 + Hamming(7,4) ===");

  // Attacher le pin au LEDC avec une fréquence initiale
  bool ok = ledcAttach(PIN_LED, FREQ_BIT0, LEDC_RESOLUTION);
  if (ok) Serial.println("LED FSK   : ✅");
  else    Serial.println("LED FSK   : ❌");

  // Initialiser DHT22
  dht.begin();
  Serial.println("DHT22     : ✅");

  // Initialiser AES
  mbedtls_aes_init(&aes);
  if (mbedtls_aes_setkey_enc(&aes, aes_key, 128) == 0) {
    Serial.println("AES-128   : ✅");
  } else {
    Serial.println("AES-128   : ❌");
  }

  Serial.println("Hamming(7,4): ✅ (ECC activé)");
  delay(2000);
}

// ============================================================
//   LOOP
// ============================================================
void loop() {
  // --- Lecture DHT22 ---
  float temperature = dht.readTemperature();
  float humidite    = dht.readHumidity();

  if (isnan(temperature) || isnan(humidite)) {
    Serial.println("Erreur lecture DHT22!");
    delay(2000);
    return;
  }

  // Convertir en entiers (×10 pour conserver 1 décimale)
  int temp_int = (int)(temperature * 10);
  int hum_int  = (int)(humidite   * 10);

  byte temp_high = highByte(temp_int);
  byte temp_low  = lowByte(temp_int);
  byte hum_high  = highByte(hum_int);
  byte hum_low   = lowByte(hum_int);

  // --- Préparer le bloc de 16 bytes pour AES ---
  unsigned char plaintext[16] = {0};
  plaintext[0] = temp_high;
  plaintext[1] = temp_low;
  plaintext[2] = hum_high;
  plaintext[3] = hum_low;

  // Checksum des données en clair (détection d'erreur supplémentaire)
  byte checksum = (temp_high + temp_low + hum_high + hum_low) & 0xFF;
  plaintext[4]  = checksum;

  // --- Chiffrement AES-128 ---
  unsigned char ciphertext[16];
  mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, plaintext, ciphertext);

  // --- Affichage Serial ---
  Serial.println("\n========================================");
  Serial.println(">>> TRANSMISSION CHIFFREE + ECC");
  Serial.print("Temperature: ");
  Serial.print(temperature, 1);
  Serial.println(" C");
  Serial.print("Humidite:    ");
  Serial.print(humidite, 1);
  Serial.println(" %");
  Serial.println("========================================");

  Serial.println("\nDonnees EN CLAIR (5 bytes actifs):");
  Serial.printf("  [0] Temp High : 0x%02X (%d)\n", plaintext[0], plaintext[0]);
  Serial.printf("  [1] Temp Low  : 0x%02X (%d)\n", plaintext[1], plaintext[1]);
  Serial.printf("  [2] Hum High  : 0x%02X (%d)\n", plaintext[2], plaintext[2]);
  Serial.printf("  [3] Hum Low   : 0x%02X (%d)\n", plaintext[3], plaintext[3]);
  Serial.printf("  [4] Checksum  : 0x%02X (%d)\n", plaintext[4], plaintext[4]);

  Serial.println("\nDonnees CHIFFREES AES-128 (16 bytes):");
  for (int i = 0; i < 16; i++) {
    Serial.printf("  [%2d] 0x%02X (%d)\n", i, ciphertext[i], ciphertext[i]);
  }

  Serial.println("\nMots Hamming(7,4) par byte (nibble haut | nibble bas) :");
  for (int i = 0; i < 16; i++) {
    byte nH = (ciphertext[i] >> 4) & 0x0F;
    byte nL =  ciphertext[i]       & 0x0F;
    byte wH = hammingEncode(nH);
    byte wL = hammingEncode(nL);
    Serial.printf("  [%2d] 0x%02X  → hamming_haut=0b%c%c%c%c%c%c%c  hamming_bas=0b%c%c%c%c%c%c%c\n",
      i, ciphertext[i],
      ((wH>>6)&1)?'1':'0', ((wH>>5)&1)?'1':'0', ((wH>>4)&1)?'1':'0',
      ((wH>>3)&1)?'1':'0', ((wH>>2)&1)?'1':'0', ((wH>>1)&1)?'1':'0', (wH&1)?'1':'0',
      ((wL>>6)&1)?'1':'0', ((wL>>5)&1)?'1':'0', ((wL>>4)&1)?'1':'0',
      ((wL>>3)&1)?'1':'0', ((wL>>2)&1)?'1':'0', ((wL>>1)&1)?'1':'0', (wL&1)?'1':'0'
    );
  }

  // ─────────────── TRANSMISSION ───────────────

  // 1. PRÉAMBULE : 1010101010101010 (16 bits — réduit les fausses sync)
  Serial.println("\n1. Envoi PREAMBULE: 1010101010101010 (16 bits)");
  for (int i = 0; i < 8; i++) {
    sendBit(1);
    sendBit(0);
  }

  // 2. DONNÉES : 16 bytes AES encodés en Hamming(7,4)
  //    → 16 × 14 bits = 224 bits transmis
  Serial.println("2. Envoi DONNEES CHIFFREES protegees Hamming(7,4) (16 bytes → 224 bits @ 100bps)");
  for (int i = 0; i < 16; i++) {
    sendByteHamming(ciphertext[i]);
  }

  // 3. FIN : 00000000 (8 bits)
  Serial.println("3. Envoi FIN: 00000000");
  for (int i = 0; i < 8; i++) {
    sendBit(0);
  }

  Serial.println(">>> TRANSMISSION TERMINEE\n");

  delay(3000);  // Pause entre transmissions
}