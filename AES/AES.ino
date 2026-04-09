#include <Arduino.h>

// IMPORTANT: This sketch uses a local copy of the "Crypto" library by Rhys Weatherley.
// The library files have been placed in the `src/Crypto` directory alongside this sketch,
// meaning you do not need to install any external libraries from the Arduino Library Manager.

// Local includes for the Crypto library
#include "src/Crypto/Crypto.h"
#include "src/Crypto/AES.h"
#include "src/Crypto/CBC.h"

// Optimize: We use AESTiny to drastically reduce Flash memory and SRAM consumption!
AESTiny128 aes128;
AESTiny256 aes256;
CBC<AESTiny128> cbc128;
CBC<AESTiny256> cbc256;

void setup() {
  Serial.begin(115200); 
  
  // Wait a little for the serial monitor to settle so you don't miss the first prompt
  delay(2000); 
  
  Serial.println("\n\n========================================");
  Serial.println(" Arduino AES Encryption/Decryption Tool ");
  Serial.println("========================================");
  Serial.println("IMPORTANT: Ensure Serial Monitor is set to 'Newline' and '115200 baud'");
}

// Optimized C-style string reader (no dynamic String objects memory overhead)
void readSerialInput(const char* prompt, char* buffer, int maxLength) {
  Serial.print(prompt);
  
  // Clear any stagnant data in the buffer
  while (Serial.available() > 0) {
    Serial.read();
  }
  
  int index = 0;
  while (true) {
    if (Serial.available() > 0) {
      char c = Serial.read();
      
      // Stop reading on Newline or Carriage return
      if (c == '\n' || c == '\r') {
        if (index > 0) { // If we've got data, terminate the loop
          break;
        }
      } else if (index < maxLength - 1) {
        buffer[index++] = c;
      }
    }
  }
  buffer[index] = '\0'; // Null-terminate string
  Serial.println(buffer); // Echo the input back
}

// Function to parse a hex string into a byte array
void hexStringToBytes(const char* hex, byte* bytes, int length) {
  for (int i = 0; i < length; i++) {
    char byteString[3] = {hex[i * 2], hex[i * 2 + 1], '\0'};
    bytes[i] = (byte) strtol(byteString, NULL, 16);
  }
}

// Function to print a byte array as hex
void printHex(const byte* data, int length) {
  for (int i = 0; i < length; i++) {
    if (data[i] < 0x10) Serial.print("0");
    Serial.print(data[i], HEX);
  }
  Serial.println();
}

void loop() {
  Serial.println("\n--- New AES Operation ---");
  
  char inputBuffer[65]; // Large enough for up to 64 characters

  // 1. Ask for AES Mode (ECB or CBC)
  readSerialInput("Select Mode (1 = ECB, 2 = CBC): ", inputBuffer, sizeof(inputBuffer));
  int mode = atoi(inputBuffer);
  if (mode != 1 && mode != 2) {
    Serial.println("Invalid mode. Please restart.");
    return;
  }

  // 2. Ask for Key Size
  readSerialInput("Select Key Size (1 = 128-bit, 2 = 256-bit): ", inputBuffer, sizeof(inputBuffer));
  int keyType = atoi(inputBuffer);
  if (keyType != 1 && keyType != 2) {
    Serial.println("Invalid key size. Please restart.");
    return;
  }

  int keySize = (keyType == 1) ? 16 : 32;

  // 3. Ask for Key
  char keyPrompt[64];
  sprintf(keyPrompt, "Enter %d-bit Key in HEX (%d chars): ", keySize * 8, keySize * 2);
  readSerialInput(keyPrompt, inputBuffer, sizeof(inputBuffer));
  
  byte key[32] = {0};
  hexStringToBytes(inputBuffer, key, keySize);

  // 4. Ask for IV if CBC
  byte iv[16] = {0};
  if (mode == 2) {
    readSerialInput("Enter 128-bit IV in HEX (32 chars): ", inputBuffer, sizeof(inputBuffer));
    hexStringToBytes(inputBuffer, iv, 16);
  }

  // 5. Ask for Data
  readSerialInput("Enter Data (Text, max 16 chars): ", inputBuffer, sizeof(inputBuffer));
  // Pad the input safely
  byte data[16] = {0}; 
  for (int i = 0; i < 16 && inputBuffer[i] != '\0'; i++) {
    data[i] = inputBuffer[i];
  }

  Serial.print("Data (HEX): ");
  printHex(data, 16);
  
  byte encrypted[16];
  byte decrypted[16];

  // Perform Encryption & Decryption
  if (mode == 1) {
    Serial.println("Mode: ECB");
    if (keyType == 1) {
      aes128.setKey(key, keySize);
      aes128.encryptBlock(encrypted, data);
      aes128.decryptBlock(decrypted, encrypted);
    } else {
      aes256.setKey(key, keySize);
      aes256.encryptBlock(encrypted, data);
      aes256.decryptBlock(decrypted, encrypted);
    }
  } else if (mode == 2) {
    Serial.println("Mode: CBC");
    if (keyType == 1) {
      cbc128.setKey(key, keySize);
      cbc128.setIV(iv, 16);
      cbc128.encrypt(encrypted, data, 16);
      
      // Reset IV for decryption
      cbc128.setKey(key, keySize);
      cbc128.setIV(iv, 16);
      cbc128.decrypt(decrypted, encrypted, 16);
    } else {
      cbc256.setKey(key, keySize);
      cbc256.setIV(iv, 16);
      cbc256.encrypt(encrypted, data, 16);
      
      // Reset IV for decryption
      cbc256.setKey(key, keySize);
      cbc256.setIV(iv, 16);
      cbc256.decrypt(decrypted, encrypted, 16);
    }
  }

  // Output results
  Serial.print("Encrypted (HEX): ");
  printHex(encrypted, 16);
  
  Serial.print("Decrypted (HEX): ");
  printHex(decrypted, 16);
  
  Serial.print("Decrypted String: ");
  // Safely print exactly 16 characters via null-terminated string
  char strOut[17];
  memcpy(strOut, decrypted, 16);
  strOut[16] = '\0';
  Serial.println(strOut);
  
  delay(1000); // 1-second delay before restarting the loop
}
