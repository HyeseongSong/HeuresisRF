const int BUTTON_PIN = 9;  // Attack Trigger Button
const int ANTENNA_PIN = 4; // Copper Wire Antenna Pin
const int LED_PIN = 13; 

void setup() {
  pinMode(BUTTON_PIN, INPUT_PULLUP);
  pinMode(ANTENNA_PIN, OUTPUT);
  pinMode(LED_PIN, OUTPUT);
}

void loop() {
  // Read button (LOW = pressed)
  if (digitalRead(BUTTON_PIN) == LOW) {
    // ATTACK STATE: Output a high-frequency square wave (e.g., 20 kHz tone)
    // This forces rapid edge transitions, radiating EM noise into the copper wire
    tone(ANTENNA_PIN, 20000); 
    digitalWrite(LED_PIN, (millis() / 50) % 2); 
  } else {
    // NORMAL STATE: Turn off antenna output (Baseline ambient state)
    noTone(ANTENNA_PIN);
    digitalWrite(ANTENNA_PIN, LOW);
    digitalWrite(LED_PIN, LOW);
  }
}
