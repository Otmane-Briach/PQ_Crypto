Post-Quantum Crypto en Wi-Fi y BLE con ESP32 (Kyber & Dilithium)

Implementación de criptografía post-cuántica (PQC) en ESP32 usando Kyber (KEM) para intercambio de claves y Dilithium (firmas), con dos transportes:

Wi-Fi + TLS 1.3 (wolfSSL)

BLE GATT con fragmentación y cifrado autenticado a nivel de aplicación.

Características

TLS 1.3 en Wi-Fi con suites híbridas/PQC (según soporte de tu build de wolfSSL).

Handshake Kyber sobre BLE con fragmentación MTU-aware.

AES-GCM/ChaCha20-Poly1305 para datos (clave derivada del KEM).

Métricas básicas: latencia de handshake, uso de memoria y throughput.

🧱 Arquitectura rápida
/firmware
  /wifi_client        # Cliente TLS 1.3 (wolfSSL) → servidor remoto
  /ble_server         # Servidor GATT en ESP32 (o cliente, según rol)
  /common
    crypto_kem.c/.h   # Kyber (KEM): encapsulado/decapsulado
    crypto_sig.c/.h   # Dilithium: firmar/verificar (opcional)
    aead.c/.h         # AES-GCM / ChaCha20-Poly1305
    fragment.c/.h     # Fragmentación/ensamblado BLE (MTU)
    kvstore.c/.h      # Claves efímeras / rotación
/tools
  bench.py            # Script de pruebas (throughput/latencia vía UART)

🧩 Requisitos

ESP-IDF ≥ 5.x (idf.py) — objetivo esp32.

wolfSSL compilado con soporte PQC (opcional si solo usas BLE a nivel app).

Alternativa PQC: PQClean/liboqs (si prefieres KEM/firmas sin TLS).

Python 3.x para scripts.

⚙️ Compilación (ESP-IDF)
# 1) Clona con submódulos si usas wolfSSL/PQClean
git clone --recurse-submodules https://github.com/tuusuario/tu-repo-pq-esp32.git
cd tu-repo-pq-esp32

# 2) Selecciona target y configura
idf.py set-target esp32
idf.py menuconfig
# → Component config > wolfSSL (o tu wrapper) > Enable TLS 1.3 / PQC (Kyber/Dilithium)
# → Component config > Bluetooth > Enable BLE y ajusta ATT MTU (ej. 247)

# 3) Compila, flashea y monitor
idf.py build flash monitor


Si compilas wolfSSL como componente:

Activa en components/wolfssl/wolfssl/options.h (según versión/soporte):

#define WOLFSSL_TLS13
#define HAVE_KYBER
#define HAVE_DILITHIUM
#define WOLFSSL_AESGCM
#define HAVE_CHACHA && HAVE_POLY1305


Selecciona/filtra ciphersuites compatibles en la app al crear el SSL_CTX.

📶 Modo Wi-Fi (TLS 1.3 con PQC)

Flujo (cliente ESP32 → servidor TLS):

Conecta a Wi-Fi (SSID/PASS en sdkconfig o wifi_client/main/config.h).

Crea wolfSSL_CTX con TLS 1.3 y ciphersuites PQC/híbridas disponibles en tu build.

Verifica el certificado del servidor (idealmente con Dilithium si tu stack lo soporta; si no, RSA/ECDSA tradicional + KEM híbrido).

Envía/recibe datos cifrados.

Ejemplo mínimo (esqueleto):

// wifi_client/main/app.c
wolfSSL_Init();
WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
// Opcional: restringe ciphersuites (depende de tu build)
wolfSSL_CTX_set_cipher_list(ctx, "TLS13-ALL"); // Ajusta a tus suites PQC/híbridas

// ... conecta Wi-Fi, resuelve host, abre socket ...
WOLFSSL* ssl = wolfSSL_new(ctx);
wolfSSL_set_fd(ssl, sockfd);
if (wolfSSL_connect(ssl) != WOLFSSL_SUCCESS) {
    // manejo de error
}
// wolfSSL_write/read(...)


💡 Si tu build aún no expone suites PQC, puedes usar TLS 1.3 clásico y hacer KEM Kyber a nivel de aplicación tras el handshake para un canal adicional end-to-end.

🦋 Modo BLE (KEM + AEAD)

Negociación MTU (p. ej., 185–247 bytes útiles en muchos casos).

KEM Kyber sobre GATT (características PQKEM_REQ / PQKEM_RESP).

Deriva session_key y cifra datos con AES-GCM/ChaCha20-Poly1305.

Fragmentación: cada PDU lleva nonce, seq, last, tag (si AEAD por fragmento) o AEAD total del mensaje completo (más eficiente).

Pseudocódigo del flujo:

// 1) Servidor BLE publica char 'PQKEM_REQ' (write) y 'DATA' (notify)
// 2) Cliente genera (pk, sk) Kyber y envía 'pk' fragmentado
// 3) Servidor encapsula → (ct, K) y responde 'ct' fragmentado
// 4) Ambos derivan session_key = KDF(K || context)
// 5) Datos app: AEAD_encrypt(session_key, nonce, aad, plaintext) → 'DATA'


Fragmentación (esqueleto):

typedef struct {
  uint32_t seq;
  uint8_t  last;     // 0/1
  uint8_t  nonce[12];
  uint16_t payload_len;
  uint8_t  payload[...]; // <= (MTU-headers)
  uint8_t  tag[16];  // si AEAD por fragmento
} __attribute__((packed)) ble_chunk_t;

🔐 Seguridad y buenas prácticas

Claves efímeras: rota tras N mensajes o T minutos.

Borra material sensible de RAM (memset_s).

Usa TRNG del ESP32 (esp_random + DRBG).

Valida firmas Dilithium para autenticidad (opcional en BLE; en Wi-Fi lo hace TLS si tu stack lo permite).

Registra métricas, no datos sensibles.

🧪 Pruebas rápidas

Wi-Fi/TLS: levanta un servidor de eco TLS (nginx/stunnel/wolfSSL server) con suites habilitadas; ejecuta el cliente ESP32 y verifica handshake + eco.

BLE: usa un cliente Python (Bleak) o una segunda placa ESP32. Logra el KEM completo y envía un mensaje cifrado; compara hashes en ambos extremos.

Bench:

idf.py monitor | tee logs.txt
python tools/bench.py logs.txt


Métricas: t_handshake_ms, rss_kb, throughput_kbps.

🛠️ Configuración

KEM_ALG=KYBER768 (o 512/1024 según lib).

SIG_ALG=DILITHIUM3 (si firmas).

BLE_ATT_MTU=247 (ajusta a tu entorno).

AEAD=AESGCM128 (o CHACHA20_POLY1305).

Rotación de clave: KEY_ROTATE_EVERY=100 msgs / 10 min.
