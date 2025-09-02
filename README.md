# Post-Quantum Crypto en ESP32 (Kyber & Dilithium)

Implementación de **criptografía post-cuántica** en **ESP32** usando los algoritmos **Kyber (KEM)** y **Dilithium (firmas)** sobre dos protocolos de comunicación:

- **Wi-Fi** con TLS 1.3 (wolfSSL)  
- **Bluetooth Low Energy (BLE)** con fragmentación de datos y cifrado autenticado

## ✨ Características
- Intercambio de claves con Kyber y autenticación con Dilithium
- Soporte tanto para Wi-Fi como para BLE
- Fragmentación MTU-aware en BLE para manejar claves y certificados grandes
- Métricas: uso de memoria, latencia y consumo energético

## ⚙️ Requisitos
- ESP32 con **ESP-IDF 5.x**  
- wolfSSL compilado con soporte PQC  
- Python 3.x para scripts de prueba

## 🚀 Uso
```bash
git clone https://github.com/tuusuario/tu-repo.git
cd tu-repo
idf.py set-target esp32
idf.py build flash monitor
```

## 🛠️ Estructura
```
/wifi_client   -> Cliente TLS con wolfSSL
/ble_server    -> Servidor BLE con fragmentación PQC
/common        -> Funciones criptográficas y de cifrado
/tools         -> Scripts de pruebas y benchmarks
```

## 📜 Licencia
MIT (u otra a tu elección)
