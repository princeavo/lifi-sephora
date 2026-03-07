/**
 * Récepteur FSK Goertzel + Déchiffrement AES-128 + Code Correcteur Hamming(7,4)
 *
 * CORRECTION CLÉ : synchronisation temporelle ABSOLUE pour éviter la dérive.
 *
 * Problème précédent : chaque appel recevoirBitGoertzel() = 5ms sampling
 *   + ~0.5ms de calcul Goertzel → sur 240 bits : ~120ms de dérive cumulée
 *   → le récepteur décroche de la fenêtre du transmetteur.
 *
 * Solution : après le préambule, chaque bit est daté par rapport à un
 *   instant de référence absolu (g_frameStartUs), éliminant toute dérive.
 *
 * Trame attendue : PRÉAMBULE(8) + 16 × 14 bits Hamming(7,4) + FIN(8) = 240 bits
 **/

#include "mbedtls/aes.h"

// Clé AES-128 (16 bytes) - Identique à l'émetteur
unsigned char aes_key[16] = {
  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
  0xab, 0xf7, 0x97, 0x46, 0x09, 0xcf, 0x4f, 0x3c
};
mbedtls_aes_context aes;

#define PIN_PD          34
#define FREQ_BIT0       1000    // 1 kHz → bit 0
#define FREQ_BIT1       2000    // 2 kHz → bit 1
#define SAMPLE_RATE     10000   // 10 kHz d'échantillonnage
#define N_SAMPLES       100     // 100 × 100µs = 10ms par bit
#define BIT_DURATION_US 10000UL // durée d'un bit en microsecondes (100 bps)

// Coefficients Goertzel précalculés
float coeff_1000;
float coeff_2000;

// ─── Synchronisation temporelle absolue ─────────────────────────────────────
// Après détection du préambule, g_frameStartUs = micros() au moment où le
// premier bit DATA doit commencer. g_frameBitCount est l'index du prochain bit.
static unsigned long g_frameStartUs  = 0;
static int           g_frameBitCount = 0;

// ============================================================
//   NOYAU GOERTZEL — partagé par les deux modes de réception
// ============================================================
/**
 * Lance une acquisition de N_SAMPLES sur le photodetecteur,
 * normalise, calcule les magnitudes 1kHz et 2kHz via Goertzel,
 * puis retourne 0 ou 1.
 *
 * @param sampleOffsetUs  offset en µs par rapport à micros() quand appeler
 *                        ce début d'acquisition (0 = immédiatement)
 */
bool goertzelDecide(unsigned long startUs) {
  // Attendre le début de la fenêtre de sampling
  while ((long)(micros() - startUs) < 0) { /* busy-wait */ }

  int samples[N_SAMPLES];
  unsigned long t0 = micros();
  for (int i = 0; i < N_SAMPLES; i++) {
    samples[i] = analogRead(PIN_PD);
    while (micros() - t0 < (unsigned long)(i + 1) * 100UL) { /* busy-wait */ }
  }

  // Seuil local min/max
  int localMin = 4095, localMax = 0;
  for (int i = 0; i < N_SAMPLES; i++) {
    if (samples[i] < localMin) localMin = samples[i];
    if (samples[i] > localMax) localMax = samples[i];
  }
  int localSeuil = (localMin + localMax) / 2;

  // Normaliser
  int normed[N_SAMPLES];
  for (int i = 0; i < N_SAMPLES; i++) normed[i] = samples[i] - localSeuil;

  // Goertzel 1000 Hz
  float q0_1 = 0, q1_1 = 0, q2_1 = 0;
  for (int i = 0; i < N_SAMPLES; i++) {
    q0_1 = coeff_1000 * q1_1 - q2_1 + normed[i];
    q2_1 = q1_1; q1_1 = q0_1;
  }
  float mag1 = sqrt(q1_1*q1_1 + q2_1*q2_1 - q1_1*q2_1*coeff_1000);

  // Goertzel 2000 Hz
  float q0_2 = 0, q1_2 = 0, q2_2 = 0;
  for (int i = 0; i < N_SAMPLES; i++) {
    q0_2 = coeff_2000 * q1_2 - q2_2 + normed[i];
    q2_2 = q1_2; q1_2 = q0_2;
  }
  float mag2 = sqrt(q1_2*q1_2 + q2_2*q2_2 - q1_2*q2_2*coeff_2000);

  float ratio = mag2 / (mag1 + 1.0f);
  return (ratio > 1.2f) ? 1 : 0;
}

// ============================================================
//   MODE LIBRE — utilisé pendant la RECHERCHE de synchronisation
//   Pas de référence absolue ; chaque bit dure exactement BIT_DURATION_US
// ============================================================
bool recevoirBitLibre() {
  return goertzelDecide(micros());
}

// ============================================================
//   MODE ABSOLU — utilisé pour les DONNÉES après synchronisation
//   Chaque bit est cadencé sur g_frameStartUs pour éviter toute dérive.
// ============================================================
bool recevoirBitAbsolu() {
  unsigned long bitStart = g_frameStartUs + (unsigned long)g_frameBitCount * BIT_DURATION_US;
  g_frameBitCount++;
  return goertzelDecide(bitStart);  // attend bitStart puis sample
}

// ============================================================
//   CODE CORRECTEUR D'ERREUR — HAMMING(7,4) — DÉCODAGE
// ============================================================
/**
 * Décode un mot Hamming de 7 bits, corrige automatiquement 1 bit erroné.
 *
 * Disposition reçue (bit6..bit0) : d4 d3 d2 p3 d1 p2 p1
 *   r[1]=p1, r[2]=p2, r[3]=d1, r[4]=p3, r[5]=d2, r[6]=d3, r[7]=d4
 *
 * Syndromes :
 *   s1 = r[1]^r[3]^r[5]^r[7]  (positions 1,3,5,7)
 *   s2 = r[2]^r[3]^r[6]^r[7]  (positions 2,3,6,7)
 *   s3 = r[4]^r[5]^r[6]^r[7]  (positions 4,5,6,7)
 *   syndrome = s3<<2 | s2<<1 | s1  → position du bit erroné (1..7), 0=OK
 */
byte hammingDecode(byte word7, bool &corrected, bool &uncorrectable) {
  corrected     = false;
  uncorrectable = false;

  byte r[8] = {0};
  for (int i = 1; i <= 7; i++) r[i] = (word7 >> (i - 1)) & 1;

  byte s1 = r[1] ^ r[3] ^ r[5] ^ r[7];
  byte s2 = r[2] ^ r[3] ^ r[6] ^ r[7];
  byte s3 = r[4] ^ r[5] ^ r[6] ^ r[7];
  byte syndrome = (s3 << 2) | (s2 << 1) | s1;

  if (syndrome != 0) {
    if (syndrome >= 1 && syndrome <= 7) {
      r[syndrome] ^= 1;  // corriger le bit erroné
      corrected = true;
    } else {
      uncorrectable = true;
    }
  }

  // Extraire les 4 bits de données : d1=r[3], d2=r[5], d3=r[6], d4=r[7]
  return (r[3] << 0) | (r[5] << 1) | (r[6] << 2) | (r[7] << 3);
}

// ============================================================
//   RÉCEPTION D'UN BYTE VIA HAMMING(7,4) — MODE ABSOLU
// ============================================================
/**
 * Reçoit 14 bits (7+7) en mode absolu, reconstruit 1 byte AES.
 * Nibble haut reçu en premier, nibble bas ensuite.
 */
byte recevoirByteHamming(bool *corrected_out, bool *uncorrectable_out) {
  *corrected_out    = false;
  *uncorrectable_out = false;

  // Nibble haut : 7 bits (MSB en premier, bit6..bit0)
  byte wordHigh = 0;
  for (int i = 6; i >= 0; i--) {
    if (recevoirBitAbsolu()) wordHigh |= (1 << i);
  }

  // Nibble bas : 7 bits
  byte wordLow = 0;
  for (int i = 6; i >= 0; i--) {
    if (recevoirBitAbsolu()) wordLow |= (1 << i);
  }

  bool corrH = false, uncorrH = false;
  bool corrL = false, uncorrL = false;
  byte nibH = hammingDecode(wordHigh, corrH, uncorrH);
  byte nibL = hammingDecode(wordLow,  corrL, uncorrL);

  if (corrH || corrL)    *corrected_out    = true;
  if (uncorrH || uncorrL) *uncorrectable_out = true;

  return (nibH << 4) | (nibL & 0x0F);
}

// ============================================================
//   SYNCHRONISATION (mode libre)
// ============================================================
bool chercherSynchronisation() {
  int timeout = 0;

  while (timeout < 1000) {
    bool patternOK = true;

    // Préambule étendu : 16 bits (8 paires "10") — réduit les fausses synchronisations
    for (int i = 0; i < 8; i++) {
      bool bit1 = recevoirBitLibre();
      bool bit0 = recevoirBitLibre();

      if (bit1 != 1 || bit0 != 0) {
        patternOK = false;
        break;
      }
    }

    if (patternOK) {
      // Le préambule (16 bits) vient de se terminer.
      // Les données commencent AU PROCHAIN bit (maintenant).
      // On enregistre l'instant de référence absolu pour toute la trame.
      g_frameStartUs  = micros();
      g_frameBitCount = 0;
      Serial.println(">>> SYNCHRO OK! (horloge absolue initialisée)");
      return true;
    }

    timeout++;
  }

  return false;
}

// ============================================================
//   VÉRIFICATION DE FIN (mode absolu)
// ============================================================
bool verifierFin() {
  for (int i = 0; i < 8; i++) {
    if (recevoirBitAbsolu() != 0) return false;
  }
  return true;
}

// ============================================================
//   SETUP
// ============================================================
void setup() {
  Serial.begin(115200);
  pinMode(PIN_PD, INPUT);
  Serial.println("=== RECEPTEUR FSK GOERTZEL 1kHz/2kHz + AES-128 + Hamming(7,4) ===");
  Serial.println("    Synchronisation temporelle ABSOLUE activée (anti-dérive)");

  // Coefficients Goertzel
  float k1 = 0.5f + ((N_SAMPLES * FREQ_BIT0) / (float)SAMPLE_RATE);
  float k2 = 0.5f + ((N_SAMPLES * FREQ_BIT1) / (float)SAMPLE_RATE);
  coeff_1000 = 2.0f * cos((2.0f * PI * k1) / N_SAMPLES);
  coeff_2000 = 2.0f * cos((2.0f * PI * k2) / N_SAMPLES);

  Serial.printf("Coeff 1kHz : %.4f\n", coeff_1000);
  Serial.printf("Coeff 2kHz : %.4f\n", coeff_2000);

  // AES déchiffrement
  mbedtls_aes_init(&aes);
  if (mbedtls_aes_setkey_dec(&aes, aes_key, 128) == 0)
    Serial.println("AES-128      : ✅");
  else
    Serial.println("AES-128      : ❌");

  Serial.println("Hamming(7,4) : ✅ (ECC + timing absolu)");
  Serial.println("En attente...\n");
}

// ============================================================
//   LOOP
// ============================================================
void loop() {
  if (chercherSynchronisation()) {
    Serial.println("\n>>> RECEPTION DONNEES CHIFFREES (Hamming + timing absolu)");

    int totalCorrected    = 0;
    int totalUncorrectable = 0;

    unsigned char ciphertext[16];
    for (int i = 0; i < 16; i++) {
      bool corr = false, uncorr = false;
      ciphertext[i] = recevoirByteHamming(&corr, &uncorr);

      if (corr) {
        totalCorrected++;
        Serial.printf("  [%2d] 0x%02X — ECC: 1 bit CORRIGÉ\n", i, ciphertext[i]);
      } else if (uncorr) {
        totalUncorrectable++;
        Serial.printf("  [%2d] 0x%02X — ECC: ERREUR NON CORRIGIBLE ⚠️\n", i, ciphertext[i]);
      }
    }

    Serial.println("\n--- Rapport ECC ---");
    Serial.printf("  Bits corrigés          : %d\n", totalCorrected);
    Serial.printf("  Erreurs non corrigibles: %d\n", totalUncorrectable);

    Serial.println(">>> Vérification FIN");
    if (verifierFin()) {
      Serial.println("FIN OK!");

      // Déchiffrement AES-128
      unsigned char plaintext[16];
      mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, ciphertext, plaintext);

      byte temp_high     = plaintext[0];
      byte temp_low      = plaintext[1];
      byte hum_high      = plaintext[2];
      byte hum_low       = plaintext[3];
      byte checksum_recu = plaintext[4];

      byte checksum_calc = (temp_high + temp_low + hum_high + hum_low) & 0xFF;

      if (checksum_recu == checksum_calc) {
        Serial.println("CHECKSUM OK!");

        int   temp_int   = (temp_high << 8) | temp_low;
        int   hum_int    = (hum_high  << 8) | hum_low;
        float temperature = temp_int / 10.0f;
        float humidite    = hum_int  / 10.0f;

        Serial.println("\n========================================");
        Serial.println("   DONNÉES DÉCHIFFRÉES ET VALIDES");
        if (totalCorrected > 0)
          Serial.printf("   ECC a corrigé %d erreur(s) de bit\n", totalCorrected);
        Serial.println("========================================");
        Serial.printf("  Température : %.1f °C\n", temperature);
        Serial.printf("  Humidité    : %.1f %%\n",  humidite);
        Serial.println("========================================\n");
      } else {
        Serial.println("ERREUR CHECKSUM! (données corrompues malgré ECC)\n");
      }
    } else {
      Serial.println("ERREUR FIN!\n");
    }

    delay(1000);
  }
}