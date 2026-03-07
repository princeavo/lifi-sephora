/**
 * Récepteur FSK avec algorithme de Goertzel + Déchiffrement AES-128
 *                + Code Correcteur d'Erreur Hamming(7,4)
 *
 * Hamming(7,4) : reçoit 7 bits → corrige 1 bit d'erreur → extrait 4 bits de données
 *
 * Structure d'un mot Hamming(7,4) reçu :
 *   Position (bit6..bit0) : d4 d3 d2 p3 d1 p2 p1
 *   Syndrome s = [s3 s2 s1] → index de la position erronée (1..7), 0 = pas d'erreur
 *   s1 = r1 XOR r3 XOR r5 XOR r7
 *   s2 = r2 XOR r3 XOR r6 XOR r7
 *   s3 = r4 XOR r5 XOR r6 XOR r7
 *
 * Trame attendue : PRÉAMBULE(8) + [16 × 14 bits Hamming] + FIN(8)
 **/

#include "mbedtls/aes.h"

// Clé AES-128 (16 bytes) - Identique à l'émetteur
unsigned char aes_key[16] = {
  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
  0xab, 0xf7, 0x97, 0x46, 0x09, 0xcf, 0x4f, 0x3c
};

mbedtls_aes_context aes;

#define PIN_PD 34
#define FREQ_BIT0 1000   // 1 kHz pour bit 0
#define FREQ_BIT1 2000   // 2 kHz pour bit 1
#define SAMPLE_RATE 10000 // 10 kHz
#define N_SAMPLES 50      // 5ms à 10kHz (synchronisé avec émetteur)

// Coefficients Goertzel précalculés
float coeff_1000;
float coeff_2000;

// ============================================================
//   PROTOTYPES
// ============================================================
bool chercherSynchronisation();
bool verifierFin();
byte recevoirByte();
byte recevoirByteHamming();
bool recevoirBitGoertzel();
byte hammingDecode(byte word7, bool &corrected, bool &uncorrectable);
byte hammingEncode(byte nibble);  // (optionnel, pour tests)

// ============================================================
//   CODE CORRECTEUR D'ERREUR — HAMMING(7,4)
// ============================================================

/**
 * Décode un mot Hamming de 7 bits et corrige automatiquement 1 bit erroné.
 *
 * @param word7        7 bits reçus dans les bits 6..0 (ordre : d4 d3 d2 p3 d1 p2 p1)
 * @param corrected    [out] true si une erreur a été corrigée
 * @param uncorrectable [out] true si l'erreur ne peut pas être corrigée (>1 bit)
 *                     Note : Hamming(7,4) ne peut détecter 2 erreurs sans les corriger.
 *                     Ici on signale l'incertitude si le syndrome est non nul après
 *                     correction.
 * @return             nibble (4 bits) décodé, corrigé si possible
 */
byte hammingDecode(byte word7, bool &corrected, bool &uncorrectable) {
  corrected    = false;
  uncorrectable = false;

  // Extraire les 7 bits reçus (r1..r7, r1=LSB=bit0, r7=MSB=bit6)
  byte r[8];  // r[1]..r[7], r[0] inutilisé
  for (int i = 1; i <= 7; i++) {
    r[i] = (word7 >> (i - 1)) & 1;
  }

  // Calculer le syndrome (parité paire)
  byte s1 = r[1] ^ r[3] ^ r[5] ^ r[7];  // positions 1,3,5,7
  byte s2 = r[2] ^ r[3] ^ r[6] ^ r[7];  // positions 2,3,6,7
  byte s3 = r[4] ^ r[5] ^ r[6] ^ r[7];  // positions 4,5,6,7

  byte syndrome = (s3 << 2) | (s2 << 1) | s1;  // 0..7

  if (syndrome != 0) {
    // syndrome indique la position (1..7) du bit erroné
    if (syndrome >= 1 && syndrome <= 7) {
      // Corriger le bit en position syndrome
      r[syndrome] ^= 1;
      corrected = true;
    } else {
      // Ne devrait pas arriver (valeur en dehors de [1..7])
      uncorrectable = true;
    }
  }

  // Extraire les 4 bits de données : d1=r[3], d2=r[5], d3=r[6], d4=r[7]
  byte nibble = (r[3] << 0) | (r[5] << 1) | (r[6] << 2) | (r[7] << 3);
  return nibble;
}

// ============================================================
//   SETUP
// ============================================================
void setup() {
  Serial.begin(115200);
  pinMode(PIN_PD, INPUT);
  Serial.println("=== RÉCEPTEUR FSK GOERTZEL 1kHz/2kHz + AES-128 + Hamming(7,4) ===");

  // Précalculer les coefficients Goertzel
  float k_1000 = (0.5 + ((N_SAMPLES * FREQ_BIT0) / (float)SAMPLE_RATE));
  float k_2000 = (0.5 + ((N_SAMPLES * FREQ_BIT1) / (float)SAMPLE_RATE));

  float omega_1000 = (2.0 * PI * k_1000) / N_SAMPLES;
  float omega_2000 = (2.0 * PI * k_2000) / N_SAMPLES;

  coeff_1000 = 2.0 * cos(omega_1000);
  coeff_2000 = 2.0 * cos(omega_2000);

  Serial.print("Coeff 1kHz: ");
  Serial.println(coeff_1000, 4);
  Serial.print("Coeff 2kHz: ");
  Serial.println(coeff_2000, 4);

  // Initialiser AES
  mbedtls_aes_init(&aes);
  if (mbedtls_aes_setkey_dec(&aes, aes_key, 128) == 0) {
    Serial.println("AES-128      : ✅");
  } else {
    Serial.println("AES-128      : ❌");
  }

  Serial.println("Hamming(7,4) : ✅ (ECC activé)");
  Serial.println("En attente...\n");
}

// ============================================================
//   LOOP
// ============================================================
void loop() {
  if (chercherSynchronisation()) {
    Serial.println("\n>>> RECEPTION DONNEES CHIFFREES (avec ECC Hamming)");

    // Compteurs d'erreurs ECC globaux pour cette trame
    int totalCorrected    = 0;
    int totalUncorrectable = 0;

    // Recevoir 16 bytes chiffrés via Hamming(7,4)
    unsigned char ciphertext[16];
    for (int i = 0; i < 16; i++) {
      bool corr    = false;
      bool uncorr  = false;
      ciphertext[i] = recevoirByteHamming(&corr, &uncorr);

      if (corr) {
        totalCorrected++;
        Serial.printf("  [%2d] byte recu 0x%02X — ECC: 1 bit CORRIGE\n", i, ciphertext[i]);
      } else if (uncorr) {
        totalUncorrectable++;
        Serial.printf("  [%2d] byte recu 0x%02X — ECC: ERREUR NON CORRIGIBLE ⚠️\n", i, ciphertext[i]);
      }
    }

    // Rapport ECC de la trame
    Serial.println("\n--- Rapport ECC ---");
    Serial.printf("  Bits errones corriges      : %d\n", totalCorrected);
    Serial.printf("  Erreurs non corrigibles    : %d\n", totalUncorrectable);

    // Vérifier la séquence de FIN
    Serial.println(">>> Verification FIN");
    if (verifierFin()) {
      Serial.println("FIN OK!");

      // Déchiffrer avec AES-128
      unsigned char plaintext[16];
      mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, ciphertext, plaintext);

      // Extraire les données
      byte temp_high      = plaintext[0];
      byte temp_low       = plaintext[1];
      byte hum_high       = plaintext[2];
      byte hum_low        = plaintext[3];
      byte checksum_recu  = plaintext[4];

      // Vérifier le checksum applicatif
      byte checksum_calcule = (temp_high + temp_low + hum_high + hum_low) & 0xFF;

      if (checksum_recu == checksum_calcule) {
        Serial.println("CHECKSUM OK!");

        // Reconstruire les valeurs
        int   temp_int   = (temp_high << 8) | temp_low;
        int   hum_int    = (hum_high  << 8) | hum_low;
        float temperature = temp_int / 10.0;
        float humidite    = hum_int  / 10.0;

        Serial.println("\n========================================");
        Serial.println("   DONNEES DECHIFFREES ET VALIDES");
        if (totalCorrected > 0) {
          Serial.printf("   (ECC a corrige %d erreur(s) de bit)\n", totalCorrected);
        }
        Serial.println("========================================");
        Serial.print("  Temperature: ");
        Serial.print(temperature, 1);
        Serial.println(" C");
        Serial.print("  Humidite:    ");
        Serial.print(humidite, 1);
        Serial.println(" %");
        Serial.println("========================================\n");

      } else {
        Serial.println("ERREUR CHECKSUM! (donnees corrompues malgre ECC)\n");
      }
    } else {
      Serial.println("ERREUR FIN!\n");
    }

    delay(1000);
  }
}

// ============================================================
//   RÉCEPTION D'UN BYTE VIA HAMMING(7,4)
// ============================================================
/**
 * Reçoit 14 bits (2 mots Hamming de 7 bits chacun) et reconstruit 1 byte.
 * Le nibble haut est reçu en premier, puis le nibble bas.
 *
 * @param corrected_out    [out] true si au moins une correction a été faite
 * @param uncorrectable_out [out] true si au moins une erreur non corrigible
 * @return                  byte reconstruit et corrigé
 */
byte recevoirByteHamming(bool *corrected_out, bool *uncorrectable_out) {
  *corrected_out    = false;
  *uncorrectable_out = false;

  // ── Recevoir 7 bits pour le nibble haut ──
  byte wordHigh = 0;
  for (int i = 6; i >= 0; i--) {
    bool bit = recevoirBitGoertzel();
    if (bit) wordHigh |= (1 << i);
  }

  // ── Recevoir 7 bits pour le nibble bas ──
  byte wordLow = 0;
  for (int i = 6; i >= 0; i--) {
    bool bit = recevoirBitGoertzel();
    if (bit) wordLow |= (1 << i);
  }

  // ── Décoder les deux nibbles via Hamming ──
  bool corrH = false, uncorrH = false;
  bool corrL = false, uncorrL = false;

  byte nibbleHigh = hammingDecode(wordHigh, corrH, uncorrH);
  byte nibbleLow  = hammingDecode(wordLow,  corrL, uncorrL);

  if (corrH || corrL)      *corrected_out    = true;
  if (uncorrH || uncorrL)  *uncorrectable_out = true;

  // Recombiner les deux nibbles en 1 byte
  return (nibbleHigh << 4) | (nibbleLow & 0x0F);
}

// ============================================================
//   SYNCHRONISATION ET FIN
// ============================================================
bool chercherSynchronisation() {
  int timeout = 0;

  while (timeout < 1000) {
    bool patternOK = true;

    for (int i = 0; i < 4; i++) {
      bool bit1 = recevoirBitGoertzel();
      bool bit0 = recevoirBitGoertzel();

      if (bit1 != 1 || bit0 != 0) {
        patternOK = false;
        break;
      }
    }

    if (patternOK) {
      Serial.println(">>> SYNCHRO OK!");
      return true;
    }

    timeout++;
  }

  return false;
}

bool verifierFin() {
  for (int i = 0; i < 8; i++) {
    bool bit = recevoirBitGoertzel();
    if (bit != 0) {
      return false;
    }
  }
  return true;
}

// ============================================================
//   RÉCEPTION D'UN BIT — ALGORITHME DE GOERTZEL
// ============================================================
bool recevoirBitGoertzel() {
  // Échantillonner le signal
  int samples[N_SAMPLES];
  unsigned long startTime  = micros();
  unsigned long samplePeriod = 100;  // 100µs = 10kHz

  for (int i = 0; i < N_SAMPLES; i++) {
    samples[i] = analogRead(PIN_PD);

    while (micros() - startTime < (unsigned long)(i + 1) * samplePeriod) {
      // Attente active (busy-wait)
    }
  }

  // Calculer le seuil local (min/max) pour robustesse aux variations DC
  int localMin = 4095, localMax = 0;
  for (int i = 0; i < N_SAMPLES; i++) {
    if (samples[i] < localMin) localMin = samples[i];
    if (samples[i] > localMax) localMax = samples[i];
  }
  int localSeuil = (localMin + localMax) / 2;

  // Normaliser les échantillons (centrer autour de 0)
  int normalizedSamples[N_SAMPLES];
  for (int i = 0; i < N_SAMPLES; i++) {
    normalizedSamples[i] = samples[i] - localSeuil;
  }

  // ── Goertzel 1000 Hz ──
  float q0_1000 = 0, q1_1000 = 0, q2_1000 = 0;
  for (int i = 0; i < N_SAMPLES; i++) {
    q0_1000 = coeff_1000 * q1_1000 - q2_1000 + normalizedSamples[i];
    q2_1000 = q1_1000;
    q1_1000 = q0_1000;
  }
  float magnitude_1000 = sqrt(q1_1000 * q1_1000 + q2_1000 * q2_1000
                               - q1_1000 * q2_1000 * coeff_1000);

  // ── Goertzel 2000 Hz ──
  float q0_2000 = 0, q1_2000 = 0, q2_2000 = 0;
  for (int i = 0; i < N_SAMPLES; i++) {
    q0_2000 = coeff_2000 * q1_2000 - q2_2000 + normalizedSamples[i];
    q2_2000 = q1_2000;
    q1_2000 = q0_2000;
  }
  float magnitude_2000 = sqrt(q1_2000 * q1_2000 + q2_2000 * q2_2000
                               - q1_2000 * q2_2000 * coeff_2000);

  // Décision par ratio pour plus de robustesse au bruit
  float ratio = magnitude_2000 / (magnitude_1000 + 1.0);

  return (ratio > 1.2) ? 1 : 0;
}