# PQ_Crypto

**Implementación de Criptografía Post‑Cuántica (Kyber y Dilithium) en ESP32**

Este repositorio demuestra cómo aplicar criptografía post‑cuántica en un ESP32 usando los algoritmos:
- Kyber para intercambio de claves (KEM)
- Dilithium para firmas (autenticidad)

Protocolos soportados:
- Wi-Fi con TLS 1.3 (wolfSSL)
- BLE (Bluetooth Low Energy) con fragmentación MTU-aware y cifrado autenticado

---

## Características principales
- Intercambio de claves Kyber, autenticación opcional con Dilithium
- Funcionamiento sobre Wi-Fi (TLS) y BLE (aplicación)
- Mecanismo de fragmentación para BLE con cifrado AES-GCM o ChaCha20‑Poly1305
- Medición básica: latencia de handshake, uso de memoria y consumo energético

---

## Requisitos
- ESP‑IDF versión 5.x o superior
- wolfSSL compilado con soporte para Kyber y Dilithium (si usas TLS post-cuántico)
- Alternativa PQC solo a nivel de aplicación: liboqs, PQClean
- Python 3 (para scripts de pruebas y benchmarks)

---

## Uso rápido
git clone https://github.com/Otmane-Briach/PQ_Crypto.git
cd PQ_Crypto
idf.py set-target esp32
idf.py build flash monitor

---

## Estructura del repositorio
/wifi_client   – Cliente TLS con wolfSSL
/ble_server    – Servidor BLE que implementa fragmentación y cifrado PQC
/common        – Implementaciones de Kyber, Dilithium, AEAD, fragmentación
/tools         – Scripts de prueba y benchmarking

---

## Seguridad y buenas prácticas
- Generación segura de claves con el TRNG del ESP32
- Rotación de claves efímeras tras N mensajes o T minutos
- Limpieza de memoria sensible (memset_s)
- Uso de contextos seguros y aleatoriedad para nonces y cifrado AEAD

---

## Licencia
Licencia MIT (o la que prefieras). Si integras wolfSSL, liboqs o PQClean, asegúrate de cumplir con sus licencias propias.

---

## Posibles mejoras futuras
- Medición de consumo energético total (Wi-Fi vs BLE)
- Integración de certificados Dilithium en el handshake TLS
- Soporte BLE tanto para periférico como central
- Implementación de canal seguro end‑to‑end sobre BLE usando KEM de aplicación
