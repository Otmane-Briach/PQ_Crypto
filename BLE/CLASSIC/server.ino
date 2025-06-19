/*
 * 
 * --------------------------------------------------------------------
 * ECDH (SECP256R1) para intercambio de claves usando wolfSSL
 * SHA256 simple para derivar clave AES 
 * AES-CBC + HMAC-SHA-256 para datos de temperatura
 * Métricas estandarizadas completas para comparación vs PQC
 * 
 * ------------------------------------------------------------------
 */

#include <Arduino.h>
#include <NimBLEDevice.h>

// wolfSSL headers
#include <wolfssl.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

// ============================================================================
// CONSTANTES DE OVERHEAD BLE
// ============================================================================

// Overhead típico de BLE por paquete:
// - L2CAP Header: 4 bytes
// - ATT Header: 1-3 bytes (dependiendo de la operación)
// - GATT no añade overhead adicional significativo
#define BLE_L2CAP_HEADER_SIZE    4
#define BLE_ATT_READ_HEADER_SIZE 1    // ATT Read Response
#define BLE_ATT_WRITE_HEADER_SIZE 3   // ATT Write Request
#define BLE_ATT_NOTIFY_HEADER_SIZE 3  // ATT Notification

// MTU efectivo típico después de negociación BLE
#define BLE_EFFECTIVE_MTU 247

// ─── Métricas BLE, RAM y FLASH COMPLETAS ──────────────────────────────────────────
enum BlePhase { PHASE_NONE, PHASE_HANDSHAKE, PHASE_DATA };
static BlePhase   currentPhase        = PHASE_NONE;
static uint32_t   ble_tx_bytes_phase  = 0;
static uint32_t   ble_rx_bytes_phase  = 0;
static uint32_t   ble_tx_pkts_phase   = 0;
static uint32_t   ble_rx_pkts_phase   = 0;

// Para medir el mínimo de heap libre (igual que en firmware PQC)
static size_t heap_min = SIZE_MAX;

// Para medir latencia BLE de handshake
static unsigned long handshake_start_time = 0;
static unsigned long adv_start_ms = 0;    // marca cuándo comenzó el advertising
static unsigned long first_temperature_time = 0;  // Timestamp primera temperatura

// Función unificada para imprimir métricas en formato CSV compatible
static void log_metric(const char* metric_name, unsigned long value, const char* unit) {
  Serial.printf("[METRIC_BLE_CLASSIC], %s, %lu, %s\n", metric_name, value, unit);
}

// ============================================================================
// FUNCIONES CORREGIDAS DE CONTEO DE BYTES BLE
// ============================================================================

// Función para calcular overhead total de BLE
static size_t calculate_ble_overhead(size_t payload_size, bool is_read, bool is_write, bool is_notify) {
    size_t overhead = BLE_L2CAP_HEADER_SIZE;
    
    if (is_read) {
        overhead += BLE_ATT_READ_HEADER_SIZE;
    } else if (is_write) {
        overhead += BLE_ATT_WRITE_HEADER_SIZE;
    } else if (is_notify) {
        overhead += BLE_ATT_NOTIFY_HEADER_SIZE;
    }
    
    // Si el payload + overhead > MTU, se fragmenta
    size_t total_size = payload_size + overhead;
    if (total_size > BLE_EFFECTIVE_MTU) {
        // Calcular fragmentos adicionales
        size_t extra_fragments = (total_size - BLE_EFFECTIVE_MTU + BLE_EFFECTIVE_MTU - 1) / BLE_EFFECTIVE_MTU;
        overhead += extra_fragments * 4; // 4 bytes por fragmento adicional
    }
    
    return overhead;
}

// Función para contar TX (server envía datos)
static void ble_count_tx_with_overhead(size_t payload_size, bool is_read, bool is_write, bool is_notify) {
    size_t overhead = calculate_ble_overhead(payload_size, is_read, is_write, is_notify); // overhead BLE
    size_t total_bytes = payload_size + overhead;                                           // total TX bytes
    
    ble_tx_bytes_phase += total_bytes;    // acumula bytes
    ble_tx_pkts_phase++;                  // cuenta paquetes
    
    Serial.printf(">> TX: Payload=%zu, Overhead=%zu, Total=%zu\n", payload_size, overhead, total_bytes); // debug
}


// Función para contar RX (client envía datos)
static void ble_count_rx_with_overhead(size_t payload_size, bool is_read, bool is_write, bool is_notify) {
    size_t overhead = calculate_ble_overhead(payload_size, is_read, is_write, is_notify);  
    size_t total_bytes = payload_size + overhead;    
    
    ble_rx_bytes_phase += total_bytes;    // acumulamos bytes recibidos
    ble_rx_pkts_phase++;                  // cuentamos paquetes
    
    Serial.printf(">> RX: Payload=%zu, Overhead=%zu, Total=%zu\n", payload_size, overhead, total_bytes); // debug
}


long t0_aes;

// Llamar periódicamente para actualizar el menor valor de heap disponible
static void update_heap_min() {
  size_t freeNow = esp_get_free_heap_size();
  if (freeNow < heap_min) {
    heap_min = freeNow;
  }
}

// ─── MÉTRICAS DE MEMORIA ──────────────────────────────────────────────
static void log_memory_detailed(const char* phase_tag) {
  // Heap básico
  size_t free_heap = esp_get_free_heap_size();
  size_t min_free_heap = esp_get_minimum_free_heap_size();
  size_t largest_free_block = heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT);
  
  // Información interna del heap
  multi_heap_info_t heap_info;
  heap_caps_get_info(&heap_info, MALLOC_CAP_DEFAULT);
  
  // Calcular fragmentación como en el código TLS
  float fragmentation = 0.0;
  if (free_heap > 0) {
    fragmentation = (1.0 - (float)largest_free_block / (float)free_heap) * 100.0;
  }
  
  // Stack info
  size_t stack_hwm = uxTaskGetStackHighWaterMark(NULL);
  
  // Log métricas detalladas
  log_metric((String(phase_tag) + "_Free_Heap").c_str(), free_heap, "bytes");
  log_metric((String(phase_tag) + "_Min_Free_Heap").c_str(), min_free_heap, "bytes");
  log_metric((String(phase_tag) + "_Largest_Block").c_str(), largest_free_block, "bytes");
  log_metric((String(phase_tag) + "_Stack_HWM").c_str(), stack_hwm, "bytes");
  log_metric((String(phase_tag) + "_Heap_Fragmentation").c_str(), (unsigned long)(fragmentation * 100), "percent_x100");
  log_metric((String(phase_tag) + "_Total_Free_Blocks").c_str(), heap_info.free_blocks, "count");
  log_metric((String(phase_tag) + "_Total_Allocated_Blocks").c_str(), heap_info.allocated_blocks, "count");
}

// Métricas estáticas: tamaño BSS y DATA
static void log_static_ram() {
  extern uint8_t _bss_start, _bss_end, _data_start, _data_end;
  size_t bss_size   = (size_t)(&_bss_end)   - (size_t)(&_bss_start);
  size_t data_size  = (size_t)(&_data_end)  - (size_t)(&_data_start);
  log_metric("Static_BSS_Section",   bss_size,  "bytes");
  log_metric("Static_DATA_Section",  data_size, "bytes");
}

// Métricas de FLASH (Sketch)
static void log_flash_app_size() {
  size_t used_sketch_space = ESP.getSketchSize();
  size_t free_sketch_space = ESP.getFreeSketchSpace();
  log_metric("Flash_Sketch_Used",  used_sketch_space, "bytes");
  log_metric("Flash_Sketch_Free",  free_sketch_space, "bytes");
}

// Función para resetear métricas de fase
static void ble_reset_phase(BlePhase p) {
  currentPhase       = p;
  ble_tx_bytes_phase = ble_tx_pkts_phase = 0;
  ble_rx_bytes_phase = ble_rx_pkts_phase = 0;
  if (p == PHASE_HANDSHAKE) {
    handshake_start_time = millis();
  } else {
    handshake_start_time = 0;
  }
}

// Función para volcar métricas de fase (bytes y paquetes)
static void ble_flush_phase_metrics(const char* tag) {
  log_metric(tag, ble_tx_bytes_phase, "bytes_TX");
  log_metric(tag, ble_rx_bytes_phase, "bytes_RX");
  log_metric(tag, ble_tx_pkts_phase,  "pkts_TX");
  log_metric(tag, ble_rx_pkts_phase,  "pkts_RX");
  
  // Métricas adicionales para análisis
  size_t total_bytes = ble_tx_bytes_phase + ble_rx_bytes_phase;
  log_metric((String(tag) + "_Total_Bytes").c_str(), total_bytes, "bytes");
}

// ─── MÉTRICAS DE COMPONENTES CRIPTOGRÁFICOS ─────────────────────────────────────
static void log_crypto_component_cost(const char* component, size_t before_heap, size_t after_heap) {
  if (before_heap >= after_heap) {
    size_t cost = before_heap - after_heap;
    log_metric((String(component) + "_Memory_Cost").c_str(), cost, "bytes");
  }
}

// ──────────────────────────────────────────────────────────────────────────────────

/* Constantes ECDH con wolfSSL */
#define ECC_PUB_BYTES    65    // Punto público sin comprimir SECP256R1
#define ECC_SHARED_BYTES 32    // Secreto compartido
#define AES_KEY_BYTES    32    // Clave AES-256

/* UUIDs BLE */
#define SERVICE_UUID             "12345678-1234-1234-1234-123456789012"
#define ECDH_SERVER_PUB_UUID     "13012F01-F8C3-4F4A-A8F4-15CD926DA146"
#define ECDH_CLIENT_PUB_UUID     "13012F02-F8C3-4F4A-A8F4-15CD926DA146"
#define TEMP_CHARACTERISTIC_UUID "87654321-4321-4321-4321-210987654321"

/* Constantes */
static const uint8_t BASE_IV[16]  = {
  0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
};
static const uint8_t SHA256_INFO[] = "ble-ecdh-aes";

/* wolfSSL objetos */
static WC_RNG rng;
static ecc_key serverKey;
static ecc_key clientKey;

/* Buffers */
static uint8_t server_pub[ECC_PUB_BYTES];
static uint8_t client_pub[ECC_PUB_BYTES];
static uint8_t shared_secret[ECC_SHARED_BYTES];
static uint8_t aes_key[AES_KEY_BYTES];

/* Estado BLE */
static bool deviceConnected = false;
static bool keyReady        = false;
static NimBLECharacteristic *charTemp{nullptr};
static NimBLECharacteristic *charSrvPub{nullptr};

/* Log de errores wolfSSL */
static void print_wolfssl_error(int errorCode) {
  char errorString[WOLFSSL_MAX_ERROR_SZ];
  wc_ErrorString(errorCode, errorString);
  Serial.printf("wolfSSL Error (%d): %s\n", errorCode, errorString);
}

/* Generar par ECDH con wolfSSL */
static void initECDH() {
  Serial.println("=== Iniciando generación de claves ECDH ===");
  
  // Métricas antes de inicializar wolfSSL
  size_t heap_before_wolfssl = esp_get_free_heap_size();
  log_memory_detailed("Before_wolfSSL_Init");
  
  // Inicializar RNG
  int ret = wc_InitRng(&rng);
  if (ret != 0) {
    Serial.print("ERROR: wc_InitRng falló, código: "); Serial.println(ret);
    print_wolfssl_error(ret);
    return;
  }

  // Métricas después de inicializar RNG
  size_t heap_after_rng = esp_get_free_heap_size();
  log_crypto_component_cost("RNG_Init", heap_before_wolfssl, heap_after_rng);

  // Inicializar clave ECC del servidor
  ret = wc_ecc_init_ex(&serverKey, NULL, INVALID_DEVID);
  if (ret != 0) {
    Serial.print("ERROR: wc_ecc_init_ex falló, código: "); Serial.println(ret);
    print_wolfssl_error(ret);
    return;
  }

  // Establecer RNG en la clave del servidor
  ret = wc_ecc_set_rng(&serverKey, &rng);
  if (ret != 0) {
    Serial.print("WARNING: wc_ecc_set_rng falló, código: "); Serial.println(ret);
  }

  // Métricas antes de generar claves
  size_t heap_before_keygen = esp_get_free_heap_size();
  log_memory_detailed("Before_ECC_KeyGen");
  update_heap_min();
  
  long t0 = micros();
  
  // Generar par de claves ECDH (SECP256R1)
  ret = wc_ecc_make_key(&rng, 32, &serverKey); // 32 bytes = 256 bits para SECP256R1
  
  long t1 = micros();
  
  // Métricas después de generar claves
  size_t heap_after_keygen = esp_get_free_heap_size();
  update_heap_min();
  log_memory_detailed("After_ECC_KeyGen");
  log_crypto_component_cost("ECC_KeyGen", heap_before_keygen, heap_after_keygen);

  if (ret != 0) {
    Serial.print("ERROR: wc_ecc_make_key falló, código: "); Serial.println(ret);
    print_wolfssl_error(ret);
    return;
  }

  log_metric("ECDH_KeyGen_Time", t1 - t0, "us");

  // Exportar clave pública del servidor
  word32 pubLen = ECC_PUB_BYTES;
  ret = wc_ecc_export_x963(&serverKey, server_pub, &pubLen);
  if (ret != 0 || pubLen != ECC_PUB_BYTES) {
    Serial.printf("ERROR: wc_ecc_export_x963 falló, código: %d, longitud: %u\n", ret, pubLen);
    if (ret != 0) print_wolfssl_error(ret);
    return;
  }

  // Métricas finales de inicialización
  log_memory_detailed("After_ECC_Export");
  
  Serial.println(">> Par ECDH del servidor generado correctamente con wolfSSL.");
  Serial.println("=== Generación de claves ECDH completada ===");
}


/* Derivar clave AES vía SHA256 simple (compatible con WiFi) */
static void deriveAES(){
  Serial.println("=== Iniciando derivación de clave AES ===");
  
  // Métricas antes de derivación
  size_t heap_before_derive = esp_get_free_heap_size();
  update_heap_min();
  log_memory_detailed("Before_SHA256_Derive");

  long t0 = micros();

  // Derivación simple usando SHA256 (shared_secret + info)
  wc_Sha256 sha;
  int ret = wc_InitSha256(&sha);
  if (ret != 0) {
    Serial.print("ERROR: wc_InitSha256 falló, código: "); Serial.println(ret);
    print_wolfssl_error(ret);
    keyReady = false;
    return;
  }

  wc_Sha256Update(&sha, shared_secret, ECC_SHARED_BYTES);
  wc_Sha256Update(&sha, SHA256_INFO, sizeof(SHA256_INFO) - 1);
  
  ret = wc_Sha256Final(&sha, aes_key);
  wc_Sha256Free(&sha);

  long t1 = micros();
  
  // Métricas después de derivación
  size_t heap_after_derive = esp_get_free_heap_size();
  update_heap_min();
  log_memory_detailed("After_SHA256_Derive");
  log_crypto_component_cost("SHA256_Derive", heap_before_derive, heap_after_derive);

  if (ret != 0) {
    Serial.print("ERROR: derivación SHA256 falló, código: "); Serial.println(ret);
    print_wolfssl_error(ret);
    keyReady = false;
    return;
  }

  log_metric("SHA256_Derive_Time", t1 - t0, "us");

  keyReady = true;
  
  // Imprimir AES key derivada
  Serial.print("AES key derivada: ");
  for(int i=0;i<32;i++) Serial.printf("%02X", aes_key[i]);
  Serial.println();
  Serial.println("=== Derivación de clave AES completada ===");
}

/* Cifrar + HMAC usando wolfSSL */
static void encryptAndHmac(const char* msg,
                           uint8_t* outCipher, size_t& clen,
                           uint8_t* outTag){
  if(!keyReady) return;

  // Métricas antes de cifrado
  size_t heap_before_encrypt = esp_get_free_heap_size();
  update_heap_min();

  long t0_aes = micros();

  size_t mlen = strlen(msg);
  size_t pad  = 16 - (mlen % 16);
  size_t total = mlen + pad;
  uint8_t plain[32];
  memcpy(plain, msg, mlen);
  memset(plain + mlen, pad, pad);

  // Generar IV
  uint8_t iv[16];
  memcpy(iv, BASE_IV, 16);

  // Cifrar con AES-CBC usando wolfSSL
  Aes aes;
  int ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
  if (ret != 0) {
    Serial.print("ERROR: wc_AesInit falló, código: "); Serial.println(ret);
    print_wolfssl_error(ret);
    return;
  }

  ret = wc_AesSetKey(&aes, aes_key, AES_KEY_BYTES, iv, AES_ENCRYPTION);
  if (ret != 0) {
    Serial.print("ERROR: wc_AesSetKey falló, código: "); Serial.println(ret);
    print_wolfssl_error(ret);
    wc_AesFree(&aes);
    return;
  }

  ret = wc_AesCbcEncrypt(&aes, outCipher, plain, total);
  wc_AesFree(&aes);

  long t1_aes = micros();

  if (ret != 0) {
    Serial.print("ERROR: wc_AesCbcEncrypt falló, código: "); Serial.println(ret);
    print_wolfssl_error(ret);
    return;
  }

  clen = total;

  // Métricas AES
  log_metric("AES_Encrypt_Time", t1_aes - t0_aes, "us");

  // Calcular HMAC usando wolfSSL
  long t0_hmac = micros();
  
  Hmac hmac;
  ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
  if (ret != 0) {
    Serial.print("ERROR: wc_HmacInit falló, código: "); Serial.println(ret);
    print_wolfssl_error(ret);
    return;
  }

  ret = wc_HmacSetKey(&hmac, WC_SHA256, aes_key, AES_KEY_BYTES);
  if (ret != 0) {
    Serial.print("ERROR: wc_HmacSetKey falló, código: "); Serial.println(ret);
    print_wolfssl_error(ret);
    wc_HmacFree(&hmac);
    return;
  }

  wc_HmacUpdate(&hmac, outCipher, clen);
  ret = wc_HmacFinal(&hmac, outTag);
  wc_HmacFree(&hmac);

  long t1_hmac = micros();

  if (ret != 0) {
    Serial.print("ERROR: wc_HmacFinal falló, código: "); Serial.println(ret);
    print_wolfssl_error(ret);
    return;
  }

  // Métricas después de cifrado completo
  size_t heap_after_encrypt = esp_get_free_heap_size();
  update_heap_min();
  
  log_metric("HMAC_Compute_Time", t1_hmac - t0_hmac, "us");
  log_metric("AES_HMAC_Total_Time", t1_hmac - t0_aes, "us");
  log_crypto_component_cost("AES_HMAC_Operation", heap_before_encrypt, heap_after_encrypt);
}


/* Callback para cuando el cliente lee server_pub */
class SrvPubReadCB: public NimBLECharacteristicCallbacks {
  void onRead(NimBLECharacteristic* pChar, NimBLEConnInfo& connInfo) override {
    Serial.println("=== Cliente solicitó clave pública del servidor ===");
    
    // Servidor envía 65 bytes de clave pública ECDH como respuesta a Read
    // Incluir overhead de ATT Read Response + L2CAP + posible fragmentación
    ble_count_tx_with_overhead(sizeof(server_pub), true, false, false);
    
    Serial.printf(">> Servidor envió clave pública ECDH al cliente (%d bytes payload + overhead)\n", sizeof(server_pub));
  }
};

/* Callbacks BLE */
class SvrCB: public NimBLEServerCallbacks {
  void onConnect(NimBLEServer*, NimBLEConnInfo& info) override {
    deviceConnected = true;
    keyReady = false;

    Serial.println("=== Cliente BLE conectado ===");

    // Registra el tiempo desde que arrancó el advertising
    unsigned long conn_time = millis() - adv_start_ms;
    log_metric("BLE_Connection_Time", conn_time, "ms");

    // Métrica: arrancó handshake BLE clásico
    ble_reset_phase(PHASE_HANDSHAKE);
    
    // Resetear heap_min para esta sesión
    heap_min = SIZE_MAX;
    update_heap_min();
    
    // Métricas detalladas al conectar
    log_memory_detailed("Connection_Start");

    Serial.printf(">> Cliente conectado: %s\n", info.getAddress().toString().c_str());
  }
  
  void onDisconnect(NimBLEServer*, NimBLEConnInfo& info, int reason) override {
    deviceConnected = false;
    keyReady = false;

    Serial.println("=== Cliente BLE desconectado ===");

    // Métricas de heap mínimo de la sesión
    log_metric("Heap_Minimum_Session", heap_min, "bytes");
    log_memory_detailed("Session_End");

    // Volcar fase de handshake incompleto si nunca finalizaron handshake
    if (currentPhase == PHASE_HANDSHAKE) {
      ble_flush_phase_metrics("BLE_Handshake_Incomplete");
    } else if (currentPhase == PHASE_DATA) {
      ble_flush_phase_metrics("BLE_Data_Total_OnDisconnect");
    }
    currentPhase = PHASE_NONE;

    Serial.printf(">> Cliente desconectado: %s, motivo: %d\n", info.getAddress().toString().c_str(), reason);
    
    // Reiniciar advertising con marcador de tiempo
    Serial.println("Reanudando advertising...");
    NimBLEDevice::startAdvertising();
    adv_start_ms = millis();
  }
};

class CliKeyCB: public NimBLECharacteristicCallbacks {
  void onWrite(NimBLECharacteristic* c, NimBLEConnInfo&) override {
    auto v = c->getValue();
    if (v.size() != sizeof(client_pub)) return;
    memcpy(client_pub, v.data(), sizeof(client_pub));

    Serial.println("=== Procesando clave pública del cliente ==");

    // Cliente envió 65 bytes de clave pública ECDH como Write Request
    // Incluir overhead de ATT Write Request + L2CAP + posible fragmentación
    ble_count_rx_with_overhead(sizeof(client_pub), false, true, false);
    
    Serial.printf(">> Cliente envió clave pública ECDH al servidor (%d bytes payload + overhead)\n", sizeof(client_pub));

    // Métricas antes de procesar clave del cliente
    size_t heap_before_client_key = esp_get_free_heap_size();
    log_memory_detailed("Before_Client_Key_Process");

    // Inicializar clave ECC del cliente
    int ret = wc_ecc_init_ex(&clientKey, NULL, INVALID_DEVID);
    if (ret != 0) {
      Serial.print("ERROR: wc_ecc_init_ex (cliente) falló, código: "); Serial.println(ret);
      print_wolfssl_error(ret);
      return;
    }

    // Establecer RNG en la clave del cliente
    ret = wc_ecc_set_rng(&clientKey, &rng);
    if (ret != 0) {
      Serial.print("WARNING: wc_ecc_set_rng (cliente) falló, código: "); Serial.println(ret);
    }

    // Importar clave pública del cliente
    ret = wc_ecc_import_x963(client_pub, sizeof(client_pub), &clientKey);
    if (ret != 0) {
      Serial.print("ERROR: wc_ecc_import_x963 falló, código: "); Serial.println(ret);
      print_wolfssl_error(ret);
      wc_ecc_free(&clientKey);
      return;
    }

    // Métricas después de importar clave del cliente
    size_t heap_after_client_key = esp_get_free_heap_size();
    log_crypto_component_cost("Client_Key_Import", heap_before_client_key, heap_after_client_key);

    // Métricas antes de ECDH
    size_t heap_before_ecdh = esp_get_free_heap_size();
    update_heap_min();
    log_memory_detailed("Before_ECDH_Compute");

    // Calcular secreto compartido ECDH
    word32 outlen = ECC_SHARED_BYTES;
    unsigned long t0 = micros();
    
    ret = wc_ecc_shared_secret(&serverKey, &clientKey, shared_secret, &outlen);
    
    unsigned long t1 = micros();

    // Limpiar clave del cliente
    wc_ecc_free(&clientKey);

    if (ret != 0 || outlen != ECC_SHARED_BYTES) {
      Serial.printf("ERROR: wc_ecc_shared_secret falló, código: %d, longitud: %u\n", ret, outlen);
      if (ret != 0) print_wolfssl_error(ret);
      return;
    }

    // Métricas después de ECDH
    size_t heap_after_ecdh = esp_get_free_heap_size();
    update_heap_min();
    log_memory_detailed("After_ECDH_Compute");
    log_crypto_component_cost("ECDH_Compute", heap_before_ecdh, heap_after_ecdh);
    log_metric("ECDH_Compute_Time", t1 - t0, "us");

    // Derivar clave AES
    deriveAES();

    // Si la derivación fue exitosa ( es dcir keyReady = true), trmina handshake
    if (keyReady) {
      Serial.println("=== Handshake BLE clásico completado ===");
      
      // Métrica de handshake latency compatible
      unsigned long t_handshake_end = millis();
      log_metric("BLE_Handshake_Latency", t_handshake_end - handshake_start_time, "ms");

      // Métricas del handshake con desglose detallado
      ble_flush_phase_metrics("BLE_Handshake");
      
      // Métricas adicionales para análisis detallado
      size_t payload_only = sizeof(server_pub) + sizeof(client_pub); // 130 bytes
      size_t total_bytes = ble_tx_bytes_phase + ble_rx_bytes_phase;
      size_t protocol_overhead = total_bytes - payload_only;
      
      log_metric("BLE_Handshake_Payload_Only", payload_only, "bytes");
      log_metric("BLE_Handshake_Protocol_Overhead", protocol_overhead, "bytes");
      log_metric("BLE_Handshake_Overhead_Percent", (protocol_overhead * 100) / payload_only, "percent");

      // Métricas detalladas al completar handshake
      log_memory_detailed("Handshake_Complete");

      ble_reset_phase(PHASE_DATA);

      // Métricas: memoria al inicio de fase de datos
      update_heap_min();
      log_memory_detailed("Data_Phase_Start");
      
      Serial.printf(">> Handshake completado: Total=%zu bytes (Payload=%zu + Overhead=%zu)\n", 
                   total_bytes, payload_only, protocol_overhead);
    }
  }
};

void setup(){
  Serial.begin(115200);
  
  // Esperar serial con timeout
  unsigned long setup_start_time = millis();
  while (!Serial && (millis() - setup_start_time < 5000)) {
    delay(100);
  }
  
  Serial.println("\n\n=== ESP32 BLE Classic con Métricas Completas (CORREGIDO) ===");
  Serial.println("=== Conteo de bytes incluye overhead de protocolo BLE ===");
  Serial.println("=== Inicio de Configuración ===");
  
  // Métricas iniciales del sistema
  log_memory_detailed("System_Boot");
  
  // Inicializar wolfSSL
  size_t heap_before_wolfssl_init = esp_get_free_heap_size();
  int ret = wolfSSL_Init();
  if (ret != WOLFSSL_SUCCESS) {
    Serial.print("FATAL: wolfSSL_Init falló, código: "); Serial.println(ret);
    while (1) delay(1000);
  }
  size_t heap_after_wolfssl_init = esp_get_free_heap_size();
  log_crypto_component_cost("wolfSSL_Init", heap_before_wolfssl_init, heap_after_wolfssl_init);
  
  // Inicialización ECDH con wolfSSL
  initECDH();
  
  Serial.println("\n=== Métricas de Memoria Estática ===");
  // Métricas estáticas
  log_flash_app_size();
  log_static_ram();
  
  Serial.println("\n=== Métricas de Memoria Dinámica Inicial ===");
  update_heap_min();
  log_memory_detailed("Setup_Complete");
  
  Serial.println("=== Configuración Completada ===\n");
  
  // Arranque BLE
  Serial.println("=== Iniciando servicio BLE ===");
  size_t heap_before_ble = esp_get_free_heap_size();
  
  NimBLEDevice::init("ESP32-Classic-Sensor");
  NimBLEServer* srv = NimBLEDevice::createServer();
  srv->setCallbacks(new SvrCB());

  NimBLEService* svc = srv->createService(SERVICE_UUID);

  // Característica: Server publica su clave ECDH (65 B)
  charSrvPub = svc->createCharacteristic(
      ECDH_SERVER_PUB_UUID,
      NIMBLE_PROPERTY::READ   |
      NIMBLE_PROPERTY::NOTIFY
  );
  charSrvPub->setCallbacks(new SrvPubReadCB());
  charSrvPub->setValue(server_pub, sizeof(server_pub));

  // Característica: Cliente escribe su clave ECDH (65 B)
  auto* charCliPub = svc->createCharacteristic(
      ECDH_CLIENT_PUB_UUID,
      NIMBLE_PROPERTY::WRITE
  );
  charCliPub->setCallbacks(new CliKeyCB());

  // Característica: Temperatura cifrada + HMAC (48 B)
  charTemp = svc->createCharacteristic(
      TEMP_CHARACTERISTIC_UUID,
      NIMBLE_PROPERTY::READ   |
      NIMBLE_PROPERTY::NOTIFY
  );

  svc->start();
  NimBLEDevice::getAdvertising()->addServiceUUID(SERVICE_UUID);
  NimBLEDevice::getAdvertising()->start();
  
  size_t heap_after_ble = esp_get_free_heap_size();
  log_crypto_component_cost("BLE_Stack_Init", heap_before_ble, heap_after_ble);
  log_memory_detailed("BLE_Ready");
  
  // Inicializar marcador de tiempo de advertising
  adv_start_ms = millis();
  Serial.println("Servicio BLE iniciado y anunciando...");
  Serial.println("=== Sistema listo para conexiones ===\n");
}

void loop(){
  static int contadorTemperaturas = 0;  // Contador de notificaciones enviadas
  static uint32_t lastSend = 0;         // Para controlar el intervalo de 1 s

  if (deviceConnected && keyReady && contadorTemperaturas < 25) {
    // Esperar 1 s entre envíos (igual que otros códigos)
    if (millis() - lastSend < 1000) return;
    lastSend = millis();
    
    // Usar patrón de temperatura similar a otros códigos
    static float temperature = 25.0;
    temperature += 0.5;
    if (temperature > 35.0) temperature = 20.0;

    char txt[16];
    snprintf(txt, sizeof(txt), "%.2fC", temperature);

    //  Capturar tiempo primera temperatura 
    if (contadorTemperaturas == 0) {
        first_temperature_time = millis();
        Serial.printf("[EVENT], first_temperature_sent, %lu\n", first_temperature_time);
    }

    uint8_t cipher[32], tag[32];
    size_t clen = 0;
    encryptAndHmac(txt, cipher, clen, tag);

    if (clen) {
      // Payload: ciphertext + HMAC tag
      size_t payload_len = clen + 32; // Típicamente 16 bytes CBC + 32 bytes HMAC = 48 bytes
      
      // Contar con overhead de BLE Notification (incluye ATT + L2CAP + fragmentación si es necesario)
      ble_count_tx_with_overhead(payload_len, false, false, true);

      // Imprimir temperatura antes de enviar
      Serial.printf("Enviando temperatura (Classic) #%d: %s (%zu bytes payload + overhead)\n", 
                   contadorTemperaturas + 1, txt, payload_len);
      
      uint8_t payload[payload_len];
      memcpy(payload, cipher, clen);
      memcpy(payload + clen, tag, 32);
      charTemp->setValue(payload, payload_len);
      charTemp->notify();
      
      long send = micros();
      log_metric("AES_HMAC_Total_Time", send - t0_aes, "us");
      contadorTemperaturas++;  // Aumentar contador tras cada envío
      update_heap_min();       // Actualizar heap mínimo

      if (contadorTemperaturas == 25) {
        Serial.println("=== 25 notificaciones enviadas - Finalizando métricas ===");
         // ==========  Calcular latencia total ==========
        unsigned long last_temperature_time = millis();
        unsigned long total_latency = last_temperature_time - first_temperature_time;
        log_metric("Total_Temperature_Latency", total_latency, "ms");
        log_metric("Average_Temperature_Interval", total_latency / 24, "ms");  // 24 intervalos entre 25 temperaturas
        
        
        // Métricas finales de la fase de datos
        ble_flush_phase_metrics("BLE_Data_Total");
        log_memory_detailed("After_25_Notifications");
        
        // Métrica: heap mínimo tras 25 notificaciones
        log_metric("Heap_Minimum_After_25", heap_min, "bytes");
        
        // Métricas de resumen de la sesión completa
        Serial.println("=== RESUMEN DE SESIÓN COMPLETA ===");
        Serial.printf("Handshake: TX=%lu bytes, RX=%lu bytes\n", 
                     ble_tx_bytes_phase, ble_rx_bytes_phase);
        
        Serial.println("=== Métricas de sesión completadas ===");
      }
    }
  }
  else if (deviceConnected && keyReady && contadorTemperaturas >= 25) {
    // Ya se enviaron 25 notificaciones, no enviamos más.
    delay(100);
  }
  else if (deviceConnected && !keyReady) {
    delay(1000);
  }
  else {
    delay(100);
  }
}
