/**
 * Récepteur FSK avec algorithme de Goertzel
 * Détection précise de 1kHz et 2kHz
 */

#define PIN_PD 34
#define FREQ_BIT0 1000  // 1 kHz pour bit 0
#define FREQ_BIT1 2000  // 2 kHz pour bit 1
#define SAMPLE_RATE 10000  // 10 kHz
#define N_SAMPLES 50      // 5ms à 10kHz

// Seuil adaptatif
int valMin = 4095;
int valMax = 0;
int seuil = 2000;
unsigned long lastCalibration = 0;

// Coefficients Goertzel précalculés
float coeff_1000;
float coeff_2000;

void setup() {
  Serial.begin(115200);
  pinMode(PIN_PD, INPUT);
  Serial.println("=== RÉCEPTEUR FSK GOERTZEL 1kHz/2kHz ===");
  
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
  Serial.println("En attente...\n");
}

void loop() {
  if (chercherSynchronisation()) {
    Serial.println("\n>>> RECEPTION DONNEES");
    
    // Recevoir 4 bytes
    Serial.print("Temp High: ");
    byte temp_high = recevoirByte();
    
    Serial.print("Temp Low:  ");
    byte temp_low = recevoirByte();
    
    Serial.print("Hum High:  ");
    byte hum_high = recevoirByte();
    
    Serial.print("Hum Low:   ");
    byte hum_low = recevoirByte();
    
    // Recevoir checksum
    Serial.print("Checksum:  ");
    byte checksum_recu = recevoirByte();
    
    // Calculer checksum
    byte checksum_calcule = (temp_high + temp_low + hum_high + hum_low) & 0xFF;
    
    // Vérifier la fin
    Serial.println("\n>>> Verification FIN");
    if (verifierFin()) {
      Serial.println("FIN OK!");
      
      if (checksum_recu == checksum_calcule) {
        Serial.println("CHECKSUM OK!");
        
        // Reconstruire les valeurs
        int temp_int = (temp_high << 8) | temp_low;
        int hum_int = (hum_high << 8) | hum_low;
        
        float temperature = temp_int / 10.0;
        float humidite = hum_int / 10.0;
        
        Serial.println("\n========================================");
        Serial.println("       DONNEES VALIDES");
        Serial.println("========================================");
        Serial.print("  Temperature: ");
        Serial.print(temperature, 1);
        Serial.println(" C");
        Serial.print("  Humidite:    ");
        Serial.print(humidite, 1);
        Serial.println(" %");
        Serial.println("========================================\n");
      } else {
        Serial.println("ERREUR CHECKSUM!\n");
      }
    } else {
      Serial.println("ERREUR FIN!\n");
    }
    
    delay(1000);
  }
}

bool chercherSynchronisation() {
  int timeout = 0;
  
  while (timeout < 1000) {
    bool patternOK = true;
    
    for(int i=0; i<4; i++) {
      bool bit1 = recevoirBitGoertzel();
      bool bit0 = recevoirBitGoertzel();
      
      if(bit1 != 1 || bit0 != 0) {
        patternOK = false;
        break;
      }
    }
    
    if(patternOK) {
      Serial.println(">>> SYNCHRO OK!");
      return true;
    }
    
    timeout++;
  }
  
  return false;
}

bool verifierFin() {
  for(int i=0; i<8; i++) {
    bool bit = recevoirBitGoertzel();
    if(bit != 0) {
      return false;
    }
  }
  return true;
}

byte recevoirByte() {
  byte data = 0;
  for (int i = 7; i >= 0; i--) {
    bool bit = recevoirBitGoertzel();
    if (bit) {
      data |= (1 << i);
    }
  }
  
  for (int i = 7; i >= 0; i--) {
    Serial.print((data >> i) & 0x01);
  }
  Serial.print(" -> ");
  Serial.println(data);
  
  return data;
}

bool recevoirBitGoertzel() {
  // Échantillonner le signal
  int samples[N_SAMPLES];
  unsigned long startTime = micros();
  unsigned long samplePeriod = 100;  // 100µs = 10kHz
  
  for(int i = 0; i < N_SAMPLES; i++) {
    samples[i] = analogRead(PIN_PD);
    
    // Mise à jour seuil adaptatif
    if(samples[i] < valMin) valMin = samples[i];
    if(samples[i] > valMax) valMax = samples[i];
    
    // Attendre pour avoir 10kHz d'échantillonnage
    while(micros() - startTime < (i+1) * samplePeriod) {
      // Attente active
    }
  }
  
  // Recalculer seuil périodiquement
  if(millis() - lastCalibration > 100) {
    seuil = (valMin + valMax) / 2;
    lastCalibration = millis();
    valMin = 4095;
    valMax = 0;
  }
  
  // Normaliser les échantillons (centrer autour de 0)
  int normalizedSamples[N_SAMPLES];
  for(int i = 0; i < N_SAMPLES; i++) {
    normalizedSamples[i] = samples[i] - seuil;
  }
  
  // Calculer magnitude pour 1000Hz
  float q0_1000 = 0, q1_1000 = 0, q2_1000 = 0;
  for(int i = 0; i < N_SAMPLES; i++) {
    q0_1000 = coeff_1000 * q1_1000 - q2_1000 + normalizedSamples[i];
    q2_1000 = q1_1000;
    q1_1000 = q0_1000;
  }
  float magnitude_1000 = sqrt(q1_1000*q1_1000 + q2_1000*q2_1000 - q1_1000*q2_1000*coeff_1000);
  
  // Calculer magnitude pour 2000Hz
  float q0_2000 = 0, q1_2000 = 0, q2_2000 = 0;
  for(int i = 0; i < N_SAMPLES; i++) {
    q0_2000 = coeff_2000 * q1_2000 - q2_2000 + normalizedSamples[i];
    q2_2000 = q1_2000;
    q1_2000 = q0_2000;
  }
  float magnitude_2000 = sqrt(q1_2000*q1_2000 + q2_2000*q2_2000 - q1_2000*q2_2000*coeff_2000);
  
  // Décider quel bit
  if(magnitude_2000 > magnitude_1000) {
    return 1;  // 2000Hz dominant = bit 1
  } else {
    return 0;  // 1000Hz dominant = bit 0
  }
}