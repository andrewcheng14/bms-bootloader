#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <WiFiClient.h>

#define SERVER_PORT 8080
#define AP_SSID "ESP8266-AP"
#define AP_PASSWORD "password"

WiFiServer server(SERVER_PORT);
WiFiClient client;

void setup() {
    Serial.begin(115200, SERIAL_8N1);
    // Serial1.begin(115200, )
    // Serial.println("Starting ESP8266yuh...");
    
    WiFi.mode(WIFI_AP);
    // Serial.println("Setting up WiFi AP...");
    WiFi.softAP(AP_SSID, AP_PASSWORD);
    // Serial.println("WiFi AP setup complete.");

    server.begin();
    // Serial.println("TCP server started.");
}

void loop() {
    if (!client.connected()) {
        client = server.available();
        // if (client) {
        //     Serial.println("Client connected.");
        // }
    }

    forwardUARTPacketToSTM32();
    forwardUARTPacketToPC();
}

void forwardUARTPacketToSTM32() {
    if (client.connected() && client.available()) {
        char uartPacket[256]; // Adjust buffer size accordingly
        size_t bytesRead = client.readBytes(uartPacket, sizeof(uartPacket));
        Serial.write(uartPacket, bytesRead);
    }
}

void forwardUARTPacketToPC() {
    if (Serial.available()) {
        char uartPacket[256]; // Adjust buffer size accordingly
        size_t bytesRead = Serial.readBytes(uartPacket, sizeof(uartPacket));
        if (client.connected()) {
            client.write(uartPacket, bytesRead);
        }
    }
}
