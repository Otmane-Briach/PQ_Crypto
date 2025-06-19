//  INCLUDES Y LIBRERÍAS 
#include <NimBLEDevice.h>
#include <wolfssl.h>
#include <wolfssl/wolfcrypt/kyber.h>
#include <wolfssl/wolfcrypt/wc_kyber.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/random.h>
#include <time.h>
#include <arpa/inet.h>
#include "cert_defs.h"

// METRICS: librerías para medición de memoria
#include "esp_system.h"
#include "freertos/task.h"

extern "C" {
#include <esp_app_format.h>
}

// -------------------------------------------------------------------
// ESTRUCTURAS Y ENUMS  
// -------------------------------------------------------------------
enum BlePhase { PHASE_NONE, PHASE_HANDSHAKE, PHASE_DATA };

struct MemorySnapshot {
    size_t heap_free;
    size_t heap_used;
    size_t stack_used;
    unsigned long timestamp;
};

// -------------------------------------------------------------------
// INSTRUMENTACIÓN MÍNIMA - SOLO MEDICIONES
// -------------------------------------------------------------------

// Variables globales para medición
static uint64_t measurement_start_cycles = 0;
static unsigned long measurement_start_us = 0;
static const char* current_operation = nullptr;
static size_t current_data_size = 0;

// Obtener ciclos de CPU
static inline uint64_t get_cpu_cycles() {
    uint32_t ccount;
    __asm__ __volatile__("rsr %0, ccount" : "=a"(ccount));
    return ccount;
}

void start_measurement(const char* operation_name, size_t data_size = 0) {
    current_operation = operation_name;
    current_data_size = data_size;
    measurement_start_cycles = get_cpu_cycles();
    measurement_start_us = micros();
}

void end_measurement() {
    if (!current_operation) return;
    
    uint64_t end_cycles = get_cpu_cycles();
    unsigned long end_us = micros();
    
    // Calcular diferencias  
    uint64_t cycles_diff;
    if (end_cycles >= measurement_start_cycles) {
        cycles_diff = end_cycles - measurement_start_cycles;
    } else {
        cycles_diff = (UINT32_MAX - measurement_start_cycles) + end_cycles + 1;
    }
    
    unsigned long time_diff_us = end_us - measurement_start_us;
    
    // Log CSV simple: operación, ciclos, tiempo, tamaño datos
    Serial.printf("[RAW_METRIC], %s, %llu, %lu, %u\n", 
                  current_operation, 
                  cycles_diff, 
                  time_diff_us, 
                  (unsigned)current_data_size);
    
    current_operation = nullptr;
    current_data_size = 0;
}

#define MEASURE(operation_name, code) do { \
    start_measurement(operation_name); \
    code; \
    end_measurement(); \
} while(0)

#define MEASURE_WITH_SIZE(operation_name, data_size, code) do { \
    start_measurement(operation_name, data_size); \
    code; \
    end_measurement(); \
} while(0)

// -------------------------------------------------------------------
// CONSTANTES Y DEFINICIONES
// -------------------------------------------------------------------
#define INVALID_DEVID -1

// Kyber
#define KYBER_512_PUBLICKEY_BYTES 800
#define KYBER_512_CIPHERTEXT_BYTES 768
#define KYBER_SHARED_SECRET_BYTES 32
#define PUBKEY_CHUNK_SIZE 400
#define CIPHERTEXT_CHUNK_SIZE 384

// Dilithium
#define DILITHIUM_LEVEL 2
#define DILITHIUM_PUBKEY_SIZE 1312
#define DILITHIUM_PRIVKEY_SIZE 2560
#define DILITHIUM_SIG_SIZE 2420
#define SIGNATURE_CHUNK_SIZE 500
#define SIGNATURE_TOTAL_SIZE DILITHIUM_SIG_SIZE
#define NUM_SIGNATURE_CHUNKS 5

// AES/HMAC
#define AES_IV_BYTES 16
#define AES_CIPHERTEXT_BYTES 16
#define HMAC_BYTES 32
#define TEMPERATURE_NOTIFICATION_BYTES (AES_IV_BYTES + AES_CIPHERTEXT_BYTES + HMAC_BYTES)

// Certificados
#define SRV_CERT_LEN 3746
#define CERT_CHUNK_SIZE 512
#define NUM_CERT_CHUNKS ((SRV_CERT_LEN + CERT_CHUNK_SIZE - 1) / CERT_CHUNK_SIZE)

// Tiempos
const unsigned long KEY_LIFETIME_MS = 30000;
const unsigned long HANDSHAKE_TIMEOUT_MS = 30000;

// UUIDs BLE
#define SERVICE_UUID "12345678-1234-5678-1234-56789abcdef0"
#define TEMPERATURE_CHARACTERISTIC_UUID "12345678-1234-5678-1234-56789abcdef1"
#define KYBER_PUBKEY_CHUNK1_UUID "12345678-1234-5678-1234-56789abcdef2"
#define KYBER_PUBKEY_CHUNK2_UUID "12345678-1234-5678-1234-56789abcdef3"
#define ENCRYPTED_SESSION_KEY_CHUNK1_UUID "12345678-1234-5678-1234-56789abcdef5"
#define ENCRYPTED_SESSION_KEY_CHUNK2_UUID "12345678-1234-5678-1234-56789abcdef6"
#define DILITHIUM_SIGNATURE_CHUNK1_UUID "12345678-1234-5678-1234-56789abcdef7"
#define DILITHIUM_SIGNATURE_CHUNK2_UUID "12345678-1234-5678-1234-56789abcdef8"
#define DILITHIUM_SIGNATURE_CHUNK3_UUID "12345678-1234-5678-1234-56789abcdef9"
#define DILITHIUM_SIGNATURE_CHUNK4_UUID "12345678-1234-5678-1234-56789abcdefA"
#define DILITHIUM_SIGNATURE_CHUNK5_UUID "12345678-1234-5678-1234-56789abcdefB"
#define SRV_CERT_CHUNK1_UUID "12345678-1234-5678-1234-56789abceea0"
#define SRV_CERT_CHUNK2_UUID "12345678-1234-5678-1234-56789abceea1"
#define SRV_CERT_CHUNK3_UUID "12345678-1234-5678-1234-56789abceea2"
#define SRV_CERT_CHUNK4_UUID "12345678-1234-5678-1234-56789abceea3"
#define SRV_CERT_CHUNK5_UUID "12345678-1234-5678-1234-56789abceea4"
#define SRV_CERT_CHUNK6_UUID "12345678-1234-5678-1234-56789abceea5"
#define SRV_CERT_CHUNK7_UUID "12345678-1234-5678-1234-56789abceea6"
#define SRV_CERT_CHUNK8_UUID "12345678-1234-5678-1234-56789abceea7"
#define CLIENT_CERT_CHUNK1_UUID "12345678-1234-5678-1234-56789abcefab"
#define CLIENT_CERT_CHUNK2_UUID "12345678-1234-5678-1234-56789abcefac"

// -------------------------------------------------------------------
// VARIABLES GLOBALES
// -------------------------------------------------------------------

// Variables de memoria
extern uint8_t _bss_start, _bss_end, _data_start, _data_end;
static size_t heap_initial = 0;
static size_t heap_baseline = 0;
static size_t heap_max_used = 0;
static size_t stack_total_size = 8192;
static size_t heap_min = SIZE_MAX;

// ========== VARIABLES PARA PICOS PQC ==========
static size_t pqc_peak_heap = 0;        // Pico máximo de heap durante PQC
static size_t pqc_peak_stack = 0;       // Pico máximo de stack durante PQC
static size_t kyber_peak_heap = 0;      // Pico específico de Kyber
static size_t kyber_peak_stack = 0;
static size_t dilithium_peak_heap = 0;  // Pico específico de Dilithium
static size_t dilithium_peak_stack = 0;
static size_t aes_hmac_peak_heap = 0;   // Pico específico de AES+HMAC
static size_t aes_hmac_peak_stack = 0;
static size_t heap_before_operation = 0;




// Variables BLE
static BlePhase currentPhase = PHASE_NONE;
static uint32_t ble_tx_bytes_phase = 0;
static uint32_t ble_tx_pkts_phase = 0;
static uint32_t ble_rx_bytes_phase = 0;
static uint32_t ble_rx_pkts_phase = 0;
static unsigned long session_established_time = 0;
static unsigned long handshake_start_time = 0;
static unsigned long adv_start_ms = 0;

static unsigned long first_temperature_time = 0;  // Timestamp primera temperatura



// Características BLE
NimBLEServer* pServer = nullptr;
NimBLEService* pService = nullptr;
NimBLECharacteristic* pTemperatureCharacteristic = nullptr;
NimBLECharacteristic* pPubKeyChunk1 = nullptr;
NimBLECharacteristic* pPubKeyChunk2 = nullptr;
NimBLECharacteristic* pEncryptedSessionKeyChunk1 = nullptr;
NimBLECharacteristic* pEncryptedSessionKeyChunk2 = nullptr;
NimBLECharacteristic* pDilithiumSignatureChunk1 = nullptr;
NimBLECharacteristic* pDilithiumSignatureChunk2 = nullptr;
NimBLECharacteristic* pDilithiumSignatureChunk3 = nullptr;
NimBLECharacteristic* pDilithiumSignatureChunk4 = nullptr;
NimBLECharacteristic* pDilithiumSignatureChunk5 = nullptr;
NimBLECharacteristic* pSrvCertChunk1 = nullptr;
NimBLECharacteristic* pSrvCertChunk2 = nullptr;
NimBLECharacteristic* pSrvCertChunk3 = nullptr;
NimBLECharacteristic* pSrvCertChunk4 = nullptr;
NimBLECharacteristic* pSrvCertChunk5 = nullptr;
NimBLECharacteristic* pSrvCertChunk6 = nullptr;
NimBLECharacteristic* pSrvCertChunk7 = nullptr;
NimBLECharacteristic* pSrvCertChunk8 = nullptr;
NimBLECharacteristic* pClientCertChunk1;
NimBLECharacteristic* pClientCertChunk2;

// Variables criptográficas
static std::vector<uint8_t> clientCertBuf;
static uint8_t clientPubKey[DILITHIUM_PUBKEY_SIZE];
byte ciphertextBuffer[KYBER_512_CIPHERTEXT_BYTES];
bool chunk1Received = false;
WC_RNG rng;
KyberKey kyberKey;
byte publicKey[KYBER_512_PUBLICKEY_BYTES];
byte session_key[KYBER_SHARED_SECRET_BYTES];
bool session_key_set = false;
byte iv[AES_IV_BYTES] = {0};
dilithium_key dilithiumKey;
WC_RNG dilithiumRng;
byte dilithiumPublicKey[DILITHIUM_PUBKEY_SIZE];
byte dilithiumSignature[DILITHIUM_SIG_SIZE];
dilithium_key caDilKey;

// -------------------------------------------------------------------
// FUNCIONES BLE SIMPLES CON LOG
// -------------------------------------------------------------------

void log_ble_tx(size_t bytes) {
    Serial.printf("[BLE_TX], %u, %lu\n", (unsigned)bytes, micros());
    ble_tx_bytes_phase += bytes;
    ble_tx_pkts_phase += 1;
}

void log_ble_rx(size_t bytes) {
    Serial.printf("[BLE_RX], %u, %lu\n", (unsigned)bytes, micros());
    ble_rx_bytes_phase += bytes;
    ble_rx_pkts_phase += 1;
}

void ble_reset_phase(BlePhase p) {
    currentPhase = p;
    ble_tx_bytes_phase = ble_tx_pkts_phase = 0;
    ble_rx_bytes_phase = ble_rx_pkts_phase = 0;
    if (p == PHASE_HANDSHAKE) {
        handshake_start_time = millis();
    } else {
        handshake_start_time = 0;
    }
}

void log_metric(const char* metric_name, unsigned long value, const char* unit) {
    Serial.printf("[METRIC_BLE_PQC], %s, %lu, %s\n", metric_name, value, unit);
}

void ble_flush_phase_metrics(const char* tag) {
    log_metric(tag, ble_tx_bytes_phase, "bytes_TX");
    log_metric(tag, ble_tx_pkts_phase, "pkts_TX");
    log_metric(tag, ble_rx_bytes_phase, "bytes_RX");
    log_metric(tag, ble_rx_pkts_phase, "pkts_RX");
}

// -------------------------------------------------------------------
// FUNCIONES DE MEMORIA
// -------------------------------------------------------------------
/// Obtiene una instantánea del estado de memoria actual (heap libre, heap usado, stack usado y timestamp)
MemorySnapshot take_memory_snapshot() {
    MemorySnapshot snap;
    snap.heap_free = esp_get_free_heap_size();
    snap.heap_used = heap_initial - snap.heap_free;
    snap.stack_used = stack_total_size - uxTaskGetStackHighWaterMark(NULL);
    snap.timestamp = micros();
    return snap;
}
// Registra el costo de memoria (heap y stack) de una operación comparando snapshots antes y después
void log_operation_memory_cost(const char* operation, 
                              const MemorySnapshot& before, 
                              const MemorySnapshot& after) {
    long heap_delta = (long)after.heap_used - (long)before.heap_used;
    long stack_delta = (long)after.stack_used - (long)before.stack_used;
    
    char metric_name[64];
    snprintf(metric_name, sizeof(metric_name), "%s_Heap_Cost", operation);
    log_metric(metric_name, abs(heap_delta), heap_delta >= 0 ? "bytes_consumed" : "bytes_freed");
    
    snprintf(metric_name, sizeof(metric_name), "%s_Stack_Cost", operation);
    log_metric(metric_name, abs(stack_delta), stack_delta >= 0 ? "bytes_consumed" : "bytes_freed");
}
// Realiza seguimiento mejorado de memoria en un punto de control, actualizando mínimos, máximos y fragmentación
void enhanced_memory_tracking(const char* checkpoint) {
    size_t heap_free = esp_get_free_heap_size();
    size_t heap_used = heap_initial - heap_free;
    size_t stack_free = uxTaskGetStackHighWaterMark(NULL);
    size_t stack_used = stack_total_size - stack_free;
    
    if (heap_free < heap_min) {
        heap_min = heap_free;
    }
    if (heap_used > heap_max_used) {
        heap_max_used = heap_used;
    }
    
    char metric_name[64];
    snprintf(metric_name, sizeof(metric_name), "Heap_Used_%s", checkpoint);
    log_metric(metric_name, heap_used, "bytes");
    
    snprintf(metric_name, sizeof(metric_name), "Stack_Used_%s", checkpoint);
    log_metric(metric_name, stack_used, "bytes");
    
    size_t largest_block = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
    float fragmentation = (heap_free > 0) ? 
        (100.0f - (largest_block * 100.0f / heap_free)) : 0;
    
    snprintf(metric_name, sizeof(metric_name), "Heap_Fragmentation_%s", checkpoint);
    log_metric(metric_name, (unsigned long)(fragmentation * 100), "percent_x100");
}
// Inicializa la línea base de memoria midiendo heap libre inicial y tamaño total de stack
void init_memory_baseline() {
    heap_initial = esp_get_free_heap_size();
    log_metric("Memory_Heap_Initial", heap_initial, "bytes");
    log_metric("Memory_Stack_Total", stack_total_size, "bytes");
}
// Establece la línea base de heap después de inicializar componentes (por ejemplo, WolfSSL) y registra su sobrecarga
void set_memory_baseline() {
    heap_baseline = esp_get_free_heap_size();
    size_t wolfssl_overhead = heap_initial - heap_baseline;
    log_metric("WolfSSL_Memory_Overhead", wolfssl_overhead, "bytes");
    log_metric("Memory_Baseline_Heap", heap_baseline, "bytes");
}
// Muestra resumen de memoria de la sesión: pico de heap usado, mínimo de heap libre y consumo neto
void log_session_memory_summary() {
    log_metric("Session_Heap_Peak_Used", heap_max_used, "bytes");
    log_metric("Session_Heap_Min_Free", heap_min, "bytes");
    
    size_t final_heap = esp_get_free_heap_size();
    long net_consumed = (long)heap_initial - (long)final_heap;
    log_metric("Session_Net_Heap_Consumed", abs(net_consumed), 
               net_consumed >= 0 ? "bytes_consumed" : "bytes_leaked");
}
// Registra el tamaño de memoria estática usada por las secciones BSS y DATA en RAM
void log_static_ram() {
    size_t bss_size = (size_t)(&_bss_end) - (size_t)(&_bss_start);
    size_t data_size = (size_t)(&_data_end) - (size_t)(&_data_start);
    log_metric("Static_BSS_Section", bss_size, "bytes");
    log_metric("Static_DATA_Section", data_size, "bytes");
}
// Registra el espacio flash usado y libre para la aplicación (sketch)
void log_flash_app_size() {
    size_t used_sketch_space = ESP.getSketchSize();
    size_t free_sketch_space = ESP.getFreeSketchSpace();
    log_metric("Flash_Sketch_Used", used_sketch_space, "bytes");
    log_metric("Flash_Sketch_Free", free_sketch_space, "bytes");
}

// ============  FUNCIONES PARA PICOS PQC ============
void capture_pqc_memory_before(const char* operation) {
    heap_before_operation = esp_get_free_heap_size();
    Serial.printf("ANTES %s: heap_libre=%u\n", operation, heap_before_operation);
}

void capture_pqc_memory_after(const char* operation) {
    size_t heap_after = esp_get_free_heap_size();
    size_t operation_cost = heap_before_operation - heap_after;
    size_t stack_used = stack_total_size - uxTaskGetStackHighWaterMark(NULL);
    
    Serial.printf("DESPUÉS %s: heap_libre=%u, COSTO=%u bytes, stack=%u\n", 
                  operation, heap_after, operation_cost, stack_used);
    
    // Log del costo incremental
    char metric_name[64];
    snprintf(metric_name, sizeof(metric_name), "%s_Incremental_Cost", operation);
    log_metric(metric_name, operation_cost, "bytes");
    
    // Actualizar picos globales y específicos
    if (operation_cost > pqc_peak_heap) pqc_peak_heap = operation_cost;
    if (stack_used > pqc_peak_stack) pqc_peak_stack = stack_used;
    
    // Actualizar picos específicos por operación
    if (strstr(operation, "Kyber") != NULL) {
        if (operation_cost > kyber_peak_heap) kyber_peak_heap = operation_cost;
        if (stack_used > kyber_peak_stack) kyber_peak_stack = stack_used;
    } else if (strstr(operation, "Dilithium") != NULL) {
        if (operation_cost > dilithium_peak_heap) dilithium_peak_heap = operation_cost;
        if (stack_used > dilithium_peak_stack) dilithium_peak_stack = stack_used;
    } else if (strstr(operation, "AES") != NULL || strstr(operation, "HMAC") != NULL) {
        if (operation_cost > aes_hmac_peak_heap) aes_hmac_peak_heap = operation_cost;
        if (stack_used > aes_hmac_peak_stack) aes_hmac_peak_stack = stack_used;
    }
}

void log_pqc_peaks_final() {
    Serial.println("\n=== PICOS PQC BLE DETECTADOS ===");
    
    // Picos globales de toda la sesión PQC
    log_metric("PQC_Peak_Heap_Max", pqc_peak_heap, "bytes");
    log_metric("PQC_Peak_Stack_Max", pqc_peak_stack, "bytes");
    log_metric("PQC_Peak_Total_Max", pqc_peak_heap + pqc_peak_stack, "bytes");
    
    // Picos específicos de Kyber
    log_metric("Kyber_Peak_Heap", kyber_peak_heap, "bytes");
    log_metric("Kyber_Peak_Stack", kyber_peak_stack, "bytes");
    log_metric("Kyber_Peak_Total", kyber_peak_heap + kyber_peak_stack, "bytes");
    
    // Picos específicos de Dilithium
    log_metric("Dilithium_Peak_Heap", dilithium_peak_heap, "bytes");
    log_metric("Dilithium_Peak_Stack", dilithium_peak_stack, "bytes");
    log_metric("Dilithium_Peak_Total", dilithium_peak_heap + dilithium_peak_stack, "bytes");
    
    // Picos específicos de AES+HMAC
    log_metric("AES_HMAC_Peak_Heap", aes_hmac_peak_heap, "bytes");
    log_metric("AES_HMAC_Peak_Stack", aes_hmac_peak_stack, "bytes");
    log_metric("AES_HMAC_Peak_Total", aes_hmac_peak_heap + aes_hmac_peak_stack, "bytes");
    
    // Baseline para comparación
    size_t baseline_heap = heap_initial - esp_get_free_heap_size();
    size_t baseline_stack = stack_total_size - uxTaskGetStackHighWaterMark(NULL);
    log_metric("Baseline_Heap_End", baseline_heap, "bytes");
    log_metric("Baseline_Stack_End", baseline_stack, "bytes");
    
    Serial.printf("Kyber pico: %u heap + %u stack = %u total\n", 
                  kyber_peak_heap, kyber_peak_stack, kyber_peak_heap + kyber_peak_stack);
    Serial.printf("Dilithium pico: %u heap + %u stack = %u total\n", 
                  dilithium_peak_heap, dilithium_peak_stack, dilithium_peak_heap + dilithium_peak_stack);
    Serial.printf("AES+HMAC pico: %u heap + %u stack = %u total\n", 
                  aes_hmac_peak_heap, aes_hmac_peak_stack, aes_hmac_peak_heap + aes_hmac_peak_stack);
}

void reset_pqc_peaks() {
    pqc_peak_heap = 0;
    pqc_peak_stack = 0;
    kyber_peak_heap = 0;
    kyber_peak_stack = 0;
    dilithium_peak_heap = 0;
    dilithium_peak_stack = 0;
    aes_hmac_peak_heap = 0;
    aes_hmac_peak_stack = 0;
}

// ═══════════════════════════════════════════════════════════════════
// FUNCIONES CRIPTOGRÁFICAS
// ═══════════════════════════════════════════════════════════════════

void print_wolfssl_error(int errorCode) {
    char errorString[WOLFSSL_MAX_ERROR_SZ];
    wc_ErrorString(errorCode, errorString);
    Serial.printf("wolfSSL Error (%d): %s\n", errorCode, errorString);
}

bool initCA() {
    wc_dilithium_init(&caDilKey);
    wc_dilithium_set_level(&caDilKey, DILITHIUM_LEVEL);
    int ret_import_ca = wc_dilithium_import_public(CA_PUB, CA_PUB_LEN, &caDilKey);
    if (ret_import_ca != 0) {
        Serial.println("ERROR: import CA_PUB");
        print_wolfssl_error(ret_import_ca);
        return false;
    }
    return true;
}

bool verifyClientCert(const uint8_t* cert, size_t len, uint8_t outPub[]) {
    Serial.println();
    Serial.printf(">> Verificando certificado cliente (len=%u bytes)\n\n", (unsigned)len);

    if (len < CERT_BODY_SIZE) {
        Serial.println("   ERROR: Longitud de certificado insuficiente para cuerpo.\n");
        return false;
    }
    const word32 msgSz = CERT_BODY_SIZE;
    const word32 sigSz = len - msgSz;
    if (sigSz <= 0 || sigSz > DILITHIUM_SIG_SIZE) {
        Serial.printf("   ERROR: Longitud de firma inválida (%u) o ausente.\n", (unsigned)sigSz);
        return false;
    }

    const byte* msgPtr = cert;
    const byte* sigPtr = cert + msgSz;

    int verify_res = 0;
    int ret = 0;

    capture_pqc_memory_before("Dilithium_Verify");  
    MEASURE_WITH_SIZE("dilithium_verify", sigSz, {
        ret = wc_dilithium_verify_msg(
            sigPtr, sigSz,
            msgPtr, msgSz,
            &verify_res,
            &caDilKey
        );
    });
    capture_pqc_memory_after("Dilithium_Verify");

    if (ret != 0 || verify_res != 1) {
        Serial.printf("   ERROR: firma inválida (ret=%d, verify_res=%d)\n", ret, verify_res);
        if(ret != 0) print_wolfssl_error(ret);
        return false;
    }

    if (CERT_BODY_SIZE < DILITHIUM_PUBKEY_SIZE) {
        Serial.println("   ERROR: CERT_BODY_SIZE es menor que DILITHIUM_PUBKEY_SIZE.\n");
        return false;
    }
    const size_t CLI_PUB_OFFSET = CERT_BODY_SIZE - DILITHIUM_PUBKEY_SIZE;
    memcpy(outPub, cert + CLI_PUB_OFFSET, DILITHIUM_PUBKEY_SIZE);
    Serial.println("   Certificado válido\n");
    return true;
}

bool encryptAndAuthenticate(const char* message, uint8_t* encryptedData, size_t *encryptedLen_ptr, uint8_t* hashOutput) {
    if (!session_key_set) {
        return false;
    }

    bool success = false;
    
    start_measurement("aes_hmac", strlen(message));
    
    // Operación AES+HMAC completa
    do {
        Aes aes;
        if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) {
            Serial.println("Fallo al inicializar AES.");
            break;
        }

        if (wc_RNG_GenerateBlock(&rng, iv, sizeof(iv)) != 0) {
            Serial.println("Fallo al generar IV.");
            wc_AesFree(&aes);
            break;
        }

        if (wc_AesSetKey(&aes, session_key, sizeof(session_key), iv, AES_ENCRYPTION) != 0) {
            Serial.println("Fallo al establecer la clave AES.");
            wc_AesFree(&aes);
            break;
        }

        size_t messageLen = strlen(message);
        size_t paddedLen = ((messageLen / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;

        uint8_t paddedMessage[AES_CIPHERTEXT_BYTES];
        
        if (paddedLen > AES_CIPHERTEXT_BYTES) {
            Serial.printf("Error: Mensaje con padding (%u) demasiado grande para buffer (%u).\n", (unsigned)paddedLen, (unsigned)AES_CIPHERTEXT_BYTES);
            wc_AesFree(&aes);
            break;
        }

        memcpy(paddedMessage, message, messageLen);
        uint8_t padValue = paddedLen - messageLen;
        for (size_t i = messageLen; i < paddedLen; i++) {
            paddedMessage[i] = padValue;
        }

        if (wc_AesCbcEncrypt(&aes, encryptedData, paddedMessage, paddedLen) != 0) {
            Serial.println("Fallo el cifrado AES-CBC.");
            wc_AesFree(&aes);
            break;
        }
        wc_AesFree(&aes);
        *encryptedLen_ptr = paddedLen;

        Hmac hmac;
        if (wc_HmacInit(&hmac, NULL, INVALID_DEVID) != 0) {
            Serial.println("Fallo al inicializar HMAC.");
            break;
        }
        if (wc_HmacSetKey(&hmac, WC_SHA256, session_key, sizeof(session_key)) != 0) {
            Serial.println("Fallo al establecer la clave HMAC.");
            wc_HmacFree(&hmac);
            break;
        }
        if (wc_HmacUpdate(&hmac, iv, AES_IV_BYTES) != 0) {
            Serial.println("Fallo en HMAC update (IV).");
            wc_HmacFree(&hmac);
            break;
        }
        if (wc_HmacUpdate(&hmac, encryptedData, *encryptedLen_ptr) != 0) {
            Serial.println("Fallo en HMAC update (ciphertext).");
            wc_HmacFree(&hmac);
            break;
        }
        if (wc_HmacFinal(&hmac, hashOutput) != 0) {
            Serial.println("Fallo al finalizar HMAC.");
            wc_HmacFree(&hmac);
            break;
        }
        wc_HmacFree(&hmac);
        success = true;
    } while(0);
    
    end_measurement();
    
    return success;
}

// 
// DECLARACIONES ADELANTADAS
//  
void generateAndPublishKyberHandshake();

//  
// CALLBACKS BLE
//  

class ClientCertCallbacks : public NimBLECharacteristicCallbacks {
    void onWrite(NimBLECharacteristic* pChar, NimBLEConnInfo& connInfo) override {
        std::string v = pChar->getValue();
        log_ble_rx(v.size());

        clientCertBuf.insert(clientCertBuf.end(), v.begin(), v.end());
        Serial.printf("[INFO] Recibidos %u bytes de certificado cliente (total %u)\n",
                      (unsigned int)v.size(), (unsigned int)clientCertBuf.size());

        if (clientCertBuf.size() >= (CERT_BODY_SIZE + DILITHIUM_SIG_SIZE)) {
            Serial.println("[INFO] Certificado cliente completo recibido. Verificando...");

            MemorySnapshot before_verify = take_memory_snapshot();
            enhanced_memory_tracking("Before_Dilithium_Verify");

            long start_time = micros();
            bool ok = verifyClientCert(clientCertBuf.data(), clientCertBuf.size(), clientPubKey);
            long end_time = micros();
            
            MemorySnapshot after_verify = take_memory_snapshot();
            enhanced_memory_tracking("After_Dilithium_Verify");
            log_operation_memory_cost("Dilithium_Verify", before_verify, after_verify);

            log_metric("Dilithium_Verify", end_time - start_time, "us");

            if (!ok) {
                Serial.println("[ERROR] Certificado cliente inválido!");
                clientCertBuf.clear();
                return;
            }

            Serial.println("[INFO] Certificado cliente válido. Iniciando handshake BLE...");
            generateAndPublishKyberHandshake();
        }
    }
};

class MyServerCallbacks : public NimBLEServerCallbacks {
    void onConnect(NimBLEServer* pServer, NimBLEConnInfo& connInfo) override {
        Serial.printf("[EVENT], client_connected, %lu\n", millis());
        Serial.printf(">> Cliente conectado: %s\n", connInfo.getAddress().toString().c_str());

        unsigned long conn_time = millis() - adv_start_ms;
        log_metric("BLE_Conn_Time", conn_time, "ms");

        heap_min = SIZE_MAX;
        heap_max_used = 0;
        reset_pqc_peaks(); 
        
        enhanced_memory_tracking("Connection_Start");
        ble_reset_phase(PHASE_HANDSHAKE);
    }

    void onDisconnect(NimBLEServer* pServer, NimBLEConnInfo& connInfo, int reason) override {
        Serial.printf("[EVENT], client_disconnected, %lu\n", millis());
        Serial.printf(">> Cliente desconectado: %s, motivo: %d\n", connInfo.getAddress().toString().c_str(), reason);

        log_session_memory_summary();
        log_pqc_peaks_final(); 
        if (currentPhase == PHASE_DATA) {
            ble_flush_phase_metrics("BLE_Data_Total_OnDisconnect");
        } else if (currentPhase == PHASE_HANDSHAKE) {
            ble_flush_phase_metrics("BLE_Handshake_Incomplete_OnDisconnect");
        }
        
        currentPhase = PHASE_NONE;
        handshake_start_time = 0;
        clientCertBuf.clear();
        session_key_set = false;
        session_established_time = 0;
        chunk1Received = false;

        Serial.println("Reanudando advertising...");
        NimBLEDevice::startAdvertising();
        adv_start_ms = millis();
    }
};

class EncryptedSessionKeyCallbacks : public NimBLECharacteristicCallbacks {
public:
    void onWrite(NimBLECharacteristic* pCharacteristic, NimBLEConnInfo& connInfo) override {
        std::string uuid_str = pCharacteristic->getUUID().toString();
        std::string value = pCharacteristic->getValue();
        log_ble_rx(value.size());
        
        Serial.printf("Recibido chunk clave encapsulada: %s, longitud: %u bytes\n", uuid_str.c_str(), (unsigned int)value.size());

        size_t offset = 0;
        if (uuid_str == ENCRYPTED_SESSION_KEY_CHUNK1_UUID) {
            if (value.size() > CIPHERTEXT_CHUNK_SIZE) {
                Serial.printf("Advertencia: Tamaño de ciphertext chunk1 (%u) > esperado (%d).\n", (unsigned)value.size(), CIPHERTEXT_CHUNK_SIZE);
            }
            memcpy(ciphertextBuffer, value.c_str(), value.size());
            chunk1Received = true;
            Serial.println("Chunk1 de clave encapsulada procesado.");
            return;
        }
        else if (uuid_str == ENCRYPTED_SESSION_KEY_CHUNK2_UUID) {
            if (!chunk1Received) {
                Serial.println("Error: Chunk2 de clave encapsulada recibido antes que Chunk1.");
                return;
            }
            offset = CIPHERTEXT_CHUNK_SIZE;
            size_t expected_chunk2_size = KYBER_512_CIPHERTEXT_BYTES - CIPHERTEXT_CHUNK_SIZE;
            if (value.size() > expected_chunk2_size) {
                Serial.printf("Advertencia: Tamaño de ciphertext chunk2 (%u) > esperado (%u).\n", (unsigned)value.size(), (unsigned)expected_chunk2_size);
            }
            if (offset + value.size() > KYBER_512_CIPHERTEXT_BYTES) {
                Serial.println("Error: Desbordamiento del buffer de ciphertext al recibir chunk2.");
                chunk1Received = false;
                return;
            }
            memcpy(ciphertextBuffer + offset, value.c_str(), value.size());
            chunk1Received = false;

            Serial.println("Chunk2 de clave encapsulada procesado. Procediendo a decapsular...");

            MemorySnapshot before_decap = take_memory_snapshot();
            enhanced_memory_tracking("Before_Kyber_Decapsulate");

            int ret = 0;
            capture_pqc_memory_before("Kyber_Decapsulate");  
            MEASURE_WITH_SIZE("kyber_decapsulate", KYBER_512_CIPHERTEXT_BYTES, {
                ret = wc_KyberKey_Decapsulate(&kyberKey, session_key, ciphertextBuffer, KYBER_512_CIPHERTEXT_BYTES);
            });
            capture_pqc_memory_after("Kyber_Decapsulate");
            MemorySnapshot after_decap = take_memory_snapshot();
            enhanced_memory_tracking("After_Kyber_Decapsulate");
            log_operation_memory_cost("Kyber_Decapsulate", before_decap, after_decap);

            if (ret != 0) {
                Serial.printf("Error decapsulando la clave AES. Código: %d\n", ret);
                print_wolfssl_error(ret);
                return;
            }

            session_key_set = true;
            session_established_time = millis();
            
            enhanced_memory_tracking("Handshake_Complete");
            
            Serial.print("Shared Secret (AES Session Key) establecido: ");
            for(int i = 0; i < sizeof(session_key); i++) {
                Serial.printf("%02X", session_key[i]);
            }
            Serial.println();
            Serial.println("Clave de sesión AES compartida establecida correctamente.");
            
            if (handshake_start_time != 0) {
                unsigned long t_ble_handshake_out = millis();
                unsigned long ble_latency = t_ble_handshake_out - handshake_start_time;
                log_metric("BLE_Handshake_Latency", ble_latency, "ms");
            }

            ble_flush_phase_metrics("BLE_Handshake");
            ble_reset_phase(PHASE_DATA);
            handshake_start_time = 0;

        } else {
            Serial.println("Chunk de clave encapsulada recibido con UUID desconocido.");
        }
    }
};

// 
// FUNCIÓN DE GENERACIÓN DE HANDSHAKE KYBER
// 

void generateAndPublishKyberHandshake() {
    if (session_key_set) {
        Serial.println("\n>> INICIANDO RE-HANDSHAKE KYBER (clave expirada o solicitado)");
    }

    MemorySnapshot before_keygen = take_memory_snapshot();
    enhanced_memory_tracking("Before_Kyber_KeyGen");
    
    int ret = 0;
    capture_pqc_memory_before("Kyber_KeyGen"); 
    MEASURE("kyber_keygen", {
        ret = wc_KyberKey_Init(WC_ML_KEM_512, &kyberKey, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wc_KyberKey_MakeKey(&kyberKey, &rng);
        }
    });
    capture_pqc_memory_after("Kyber_KeyGen");

    if (ret != 0) {
        Serial.printf("Error en Kyber KeyGen: %d\n", ret);
        print_wolfssl_error(ret);
        return;
    }
    
    MemorySnapshot after_keygen = take_memory_snapshot();
    enhanced_memory_tracking("After_Kyber_KeyGen");
    log_operation_memory_cost("Kyber_KeyGen", before_keygen, after_keygen);

    ret = wc_KyberKey_EncodePublicKey(&kyberKey, publicKey, KYBER_512_PUBLICKEY_BYTES);
    if (ret != 0) {
        Serial.printf("Error en wc_KyberKey_EncodePublicKey: %d\n", ret);
        print_wolfssl_error(ret);
        return;
    }

    word32 sigLen = DILITHIUM_SIG_SIZE;

    MemorySnapshot before_sign = take_memory_snapshot();
    enhanced_memory_tracking("Before_Dilithium_Sign");

    capture_pqc_memory_before("Dilithium_Sign"); 
    MEASURE_WITH_SIZE("dilithium_sign", KYBER_512_PUBLICKEY_BYTES, {
        ret = wc_dilithium_sign_msg(publicKey, KYBER_512_PUBLICKEY_BYTES,
                                    dilithiumSignature, &sigLen,
                                    &dilithiumKey, &rng);
    });
    capture_pqc_memory_after("Dilithium_Sign");

    MemorySnapshot after_sign = take_memory_snapshot();
    enhanced_memory_tracking("After_Dilithium_Sign");
    log_operation_memory_cost("Dilithium_Sign", before_sign, after_sign);

    if (ret != 0) {
        Serial.printf("Error en wc_dilithium_sign_msg: %d\n", ret);
        print_wolfssl_error(ret);
        return;
    }

    enhanced_memory_tracking("Handshake_Generated");

    pPubKeyChunk1->setValue(publicKey, PUBKEY_CHUNK_SIZE);
    log_ble_tx(PUBKEY_CHUNK_SIZE);

    size_t chunk2Len = KYBER_512_PUBLICKEY_BYTES - PUBKEY_CHUNK_SIZE;
    pPubKeyChunk2->setValue(publicKey + PUBKEY_CHUNK_SIZE, chunk2Len);
    log_ble_tx(chunk2Len);

    NimBLECharacteristic* pcs[] = {
        pDilithiumSignatureChunk1, pDilithiumSignatureChunk2, pDilithiumSignatureChunk3,
        pDilithiumSignatureChunk4, pDilithiumSignatureChunk5
    };

    for (int i = 0; i < NUM_SIGNATURE_CHUNKS; i++) {
        size_t off = i * SIGNATURE_CHUNK_SIZE;
        size_t len_to_send = (i == NUM_SIGNATURE_CHUNKS - 1)
                           ? (sigLen - off)
                           : SIGNATURE_CHUNK_SIZE;

        if (off >= sigLen) break;
        if (off + len_to_send > sigLen) len_to_send = sigLen - off;

        if (pcs[i] != nullptr && len_to_send > 0) {
            pcs[i]->setValue(dilithiumSignature + off, len_to_send);
            log_ble_tx(len_to_send);
        } else if (pcs[i] == nullptr) {
            Serial.printf("Error: pDilithiumSignatureChunk%d es nullptr\n", i + 1);
        }
    }

    session_key_set = false;
    Serial.println("[INFO] Handshake Kyber publicado en BLE. Esperando respuesta del cliente...");
}

// 
// FUNCIONES DE CONFIGURACIÓN
// 

bool setupKyber() {
    int ret_kyber_init = wc_KyberKey_Init(WC_ML_KEM_512, &kyberKey, NULL, INVALID_DEVID);
    if (ret_kyber_init != 0) {
        Serial.println("Error inicializando estructura Kyber");
        print_wolfssl_error(ret_kyber_init);
        return false;
    }
    return true;
}

bool setupDilithium() {
    int ret_rng_dilithium = wc_InitRng(&dilithiumRng);
    if (ret_rng_dilithium != 0) {
        Serial.println("ERROR: wc_InitRng para Dilithium");
        print_wolfssl_error(ret_rng_dilithium);
        return false;
    }
    wc_dilithium_init_ex(&dilithiumKey, NULL, INVALID_DEVID);
    wc_dilithium_set_level(&dilithiumKey, DILITHIUM_LEVEL);

    int ret_import_priv = wc_dilithium_import_private(SRV_PRIV, SRV_PRIV_LEN, &dilithiumKey);
    if (ret_import_priv != 0) {
        Serial.println("ERROR: import srv_priv");
        print_wolfssl_error(ret_import_priv);
        return false;
    }

    const size_t PUB_OFFSET = CERT_BODY_SIZE - DILITHIUM_PUBKEY_SIZE;
    if (SRV_CERT_LEN >= (PUB_OFFSET + DILITHIUM_PUBKEY_SIZE)) {
        memcpy(dilithiumPublicKey, SRV_CERT + PUB_OFFSET, DILITHIUM_PUBKEY_SIZE);
        Serial.println(">> Clave pública Dilithium del servidor extraída de SRV_CERT");
    } else {
        Serial.println("ERROR: SRV_CERT demasiado corto para extraer la clave pública del servidor.");
        return false;
    }
    return true;
}

void setupBLE() {
    NimBLEDevice::init("ESP32-PQC-Sensor-V2");

    pServer = NimBLEDevice::createServer();
    pServer->setCallbacks(new MyServerCallbacks());

    pService = pServer->createService(SERVICE_UUID);

    const uint8_t* certPtr = SRV_CERT;
    const char* certUUIDs[NUM_CERT_CHUNKS] = {
        SRV_CERT_CHUNK1_UUID, SRV_CERT_CHUNK2_UUID, SRV_CERT_CHUNK3_UUID, SRV_CERT_CHUNK4_UUID,
        SRV_CERT_CHUNK5_UUID, SRV_CERT_CHUNK6_UUID, SRV_CERT_CHUNK7_UUID, SRV_CERT_CHUNK8_UUID
    };
    NimBLECharacteristic** srvChars[NUM_CERT_CHUNKS] = {
        &pSrvCertChunk1, &pSrvCertChunk2, &pSrvCertChunk3, &pSrvCertChunk4,
        &pSrvCertChunk5, &pSrvCertChunk6, &pSrvCertChunk7, &pSrvCertChunk8
    };

    for(int i = 0; i < NUM_CERT_CHUNKS; i++) {
        size_t off = i * CERT_CHUNK_SIZE;
        if (off < SRV_CERT_LEN) {
            size_t len = min((size_t)CERT_CHUNK_SIZE, (size_t)(SRV_CERT_LEN - off));
            if (certUUIDs[i] != nullptr) {
                *srvChars[i] = pService->createCharacteristic(certUUIDs[i], NIMBLE_PROPERTY::READ);
                if (*srvChars[i] != nullptr) {
                    (*srvChars[i])->setValue(certPtr + off, len);
                } else {
                    Serial.printf("Error creando característica para SRV_CERT chunk %d\n", i+1);
                }
            }
        }
    }


    // Configura las características BLE para el intercambio de certificados de cliente, claves públicas Kyber, firmas Dilithium y 
    // claves de sesión cifradas, asignando los callbacks correspondientes y arrancando el servicio
   
    ClientCertCallbacks* clientCertCallbacksInstance = new ClientCertCallbacks();
    pClientCertChunk1 = pService->createCharacteristic(CLIENT_CERT_CHUNK1_UUID, NIMBLE_PROPERTY::WRITE);
    pClientCertChunk1->setCallbacks(clientCertCallbacksInstance);

    pClientCertChunk2 = pService->createCharacteristic(CLIENT_CERT_CHUNK2_UUID, NIMBLE_PROPERTY::WRITE);
    pClientCertChunk2->setCallbacks(clientCertCallbacksInstance);

    pPubKeyChunk1 = pService->createCharacteristic(KYBER_PUBKEY_CHUNK1_UUID, NIMBLE_PROPERTY::READ);
    pPubKeyChunk2 = pService->createCharacteristic(KYBER_PUBKEY_CHUNK2_UUID, NIMBLE_PROPERTY::READ);

    pDilithiumSignatureChunk1 = pService->createCharacteristic(DILITHIUM_SIGNATURE_CHUNK1_UUID, NIMBLE_PROPERTY::READ);
    pDilithiumSignatureChunk2 = pService->createCharacteristic(DILITHIUM_SIGNATURE_CHUNK2_UUID, NIMBLE_PROPERTY::READ);
    pDilithiumSignatureChunk3 = pService->createCharacteristic(DILITHIUM_SIGNATURE_CHUNK3_UUID, NIMBLE_PROPERTY::READ);
    pDilithiumSignatureChunk4 = pService->createCharacteristic(DILITHIUM_SIGNATURE_CHUNK4_UUID, NIMBLE_PROPERTY::READ);
    pDilithiumSignatureChunk5 = pService->createCharacteristic(DILITHIUM_SIGNATURE_CHUNK5_UUID, NIMBLE_PROPERTY::READ);

    EncryptedSessionKeyCallbacks* sessionKeyCallbacksInstance = new EncryptedSessionKeyCallbacks();
    pEncryptedSessionKeyChunk1 = pService->createCharacteristic(ENCRYPTED_SESSION_KEY_CHUNK1_UUID, NIMBLE_PROPERTY::WRITE);
    pEncryptedSessionKeyChunk1->setCallbacks(sessionKeyCallbacksInstance);

    pEncryptedSessionKeyChunk2 = pService->createCharacteristic(ENCRYPTED_SESSION_KEY_CHUNK2_UUID, NIMBLE_PROPERTY::WRITE);
    pEncryptedSessionKeyChunk2->setCallbacks(sessionKeyCallbacksInstance);

    pTemperatureCharacteristic = pService->createCharacteristic(TEMPERATURE_CHARACTERISTIC_UUID, NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::NOTIFY);

    pService->start();

    NimBLEAdvertising* pAdvertising = NimBLEDevice::getAdvertising();
    pAdvertising->addServiceUUID(SERVICE_UUID);
    pAdvertising->start();

    adv_start_ms = millis();
    Serial.println("Servicio BLE iniciado y anunciando...");
}

// ------------------------------------------------ 
// FUNCIONES PRINCIPALES - SETUP Y LOOP 
// ------------------------------------------------ 

void setup() {
    // Inicia comunicación serie a 115200 baudios y espera hasta 5s a que esté disponible
    Serial.begin(115200);
    unsigned long setup_start_time = millis();
    while (!Serial && (millis() - setup_start_time < 5000)) {
        delay(100);
    }
    Serial.println("\n\n--- Inicio de Configuración ---");
    Serial.printf("[EVENT], system_boot, %lu\n", millis());
    
    // Establece línea base de memoria dinámica (heap libre inicial y stack)
    init_memory_baseline();
    
    // Inicializa WolfSSL y registra overhead de memoria
    wolfSSL_Init();
    set_memory_baseline();
    
    // Inicializa generador de números aleatorios global y verifica errores
    int ret_val = wc_InitRng(&rng);
    if (ret_val != 0) {
        Serial.println("Error inicializando RNG global. Bloqueando.");
        print_wolfssl_error(ret_val);
        while(1);
    }
    
    // Inicializa la Autoridad Certificadora basada en Dilithium
    if (!initCA()) {
        Serial.println("ERROR: Fallo inicializando CA Dilithium. Bloqueando.");
        while(1);
    }
    
    // Configura parámetros y claves de Dilithium
    if (!setupDilithium()) {
        Serial.println("Fallo en configuración Dilithium. Bloqueando.");
        while(1);
    }
    
    // Configura parámetros y claves de Kyber
    if (!setupKyber()) {
        Serial.println("Fallo inicializando Kyber. Bloqueando.");
        while(1);
    }

    // Inicializa servicios y características BLE
    setupBLE();

    // Registra métricas de memoria estática: espacio en flash y secciones BSS/DATA
    Serial.println("\n--- Baseline Static Memory Metrics ---");
    log_flash_app_size();
    log_static_ram();

    // Registra métricas de memoria dinámica en el checkpoint inicial
    Serial.println("\n--- Baseline Dynamic Memory Metrics ---");
    enhanced_memory_tracking("Initial_Setup");

    // Indica finalización de la configuración
    Serial.println("--- Configuración Completada ---\n");
}


void loop() {
    // Contadores estáticos para número de envíos y temporizador
    static int contadorTemperaturas = 0;
    static uint32_t lastSend = 0;

    // Verifica timeout del handshake y reinicia fase si excede el límite
    if (currentPhase == PHASE_HANDSHAKE && handshake_start_time != 0 && (millis() - handshake_start_time > HANDSHAKE_TIMEOUT_MS)) {
        Serial.println("[WARNING] Handshake timed out!");
        ble_flush_phase_metrics("BLE_Handshake_Timeout");
        currentPhase = PHASE_NONE;
        handshake_start_time = 0;
    }

    // Si la sesión está establecida, hay conexión y no se han enviado 25 temperaturas aún
    if (session_key_set && pServer->getConnectedCount() > 0 && contadorTemperaturas < 25) {
        // Control de intervalo de envío de 1s
        if (millis() - lastSend < 1000) return;
        lastSend = millis();

        // Simula variación de temperatura entre 20°C y 35°C
        static float temperature = 25.0;
        temperature += 0.5;
        if (temperature > 35.0) temperature = 20.0;

        char tmp[16];
        snprintf(tmp, sizeof(tmp), "%.2fC", temperature);

        // Registra el tiempo de envío de la primera temperatura
        if (contadorTemperaturas == 0) {
            first_temperature_time = millis();
            Serial.printf("[EVENT], first_temperature_sent, %lu", first_temperature_time);
        }

        // Encripta y autentica el dato de temperatura
        uint8_t encryptedData[AES_CIPHERTEXT_BYTES];
        uint8_t hmacOutput[HMAC_BYTES];
        size_t encryptedLen = 0;

        bool success = encryptAndAuthenticate(tmp, encryptedData, &encryptedLen, hmacOutput);
        if (!success) {
            Serial.println("  Error en cifrado/autenticación de temperatura");
            return;
        }

        // Construye payload con IV, texto cifrado y HMAC
        size_t payload_len = AES_IV_BYTES + encryptedLen + HMAC_BYTES;
        Serial.printf("Enviando temperatura (PQC) #%d: %s", contadorTemperaturas + 1, tmp);
        uint8_t payload[TEMPERATURE_NOTIFICATION_BYTES];
        memcpy(payload, iv, AES_IV_BYTES);
        memcpy(payload + AES_IV_BYTES, encryptedData, encryptedLen);
        memcpy(payload + AES_IV_BYTES + encryptedLen, hmacOutput, HMAC_BYTES);

        // Envía notificación BLE de temperatura
        log_ble_tx(payload_len);
        if (pTemperatureCharacteristic != nullptr) {
            pTemperatureCharacteristic->setValue(payload, payload_len);
            pTemperatureCharacteristic->notify();
        }

        contadorTemperaturas++;

        // Tras 25 envíos, calcula latencia y finaliza métricas
        if (contadorTemperaturas == 25) {
            unsigned long last_temperature_time = millis();
            unsigned long total_latency = last_temperature_time - first_temperature_time;
            log_metric("Total_Temperature_Latency", total_latency, "ms");
            log_metric("Average_Temperature_Interval", total_latency / 24, "ms");  
            ble_flush_phase_metrics("BLE_Data_Total");
            enhanced_memory_tracking("After_25_Notifications");
            Serial.printf("[EVENT], 25_notifications_sent, %lu", millis());
        }
    }
    // Si ya se enviaron 25 temperaturas y sigue conectado, espera breve
    else if (session_key_set && pServer->getConnectedCount() > 0 && contadorTemperaturas >= 25) {
        delay(100);
    }
    // Si no hay clave establecida pero existe conexión, espera antes de handshake
    else if (!session_key_set && pServer->getConnectedCount() > 0 && currentPhase != PHASE_HANDSHAKE) {
        delay(1000);
    }
    // En cualquier otro caso, espera breve para liberar CPU
    else {
        delay(100);
    }

    // Verifica expiración de la clave de sesión y gestiona re-handshake o limpieza
    if (session_key_set && (millis() - session_established_time > KEY_LIFETIME_MS)) {
        Serial.println("Vida útil de la clave de sesión expirada. Iniciando re-handshake...");
        if (pServer->getConnectedCount() > 0) {
            if (currentPhase == PHASE_DATA) {
                ble_flush_phase_metrics("BLE_Data_Before_Rekey");
            }
            ble_reset_phase(PHASE_HANDSHAKE);
            generateAndPublishKyberHandshake();
        } else {
            Serial.println("Cliente no conectado, no se puede hacer re-handshake. Limpiando clave.");
            session_key_set = false;
            session_established_time = 0;
            if (currentPhase == PHASE_DATA) {
                ble_flush_phase_metrics("BLE_Data_Before_Client_Loss_For_Rekey");
            }
            currentPhase = PHASE_NONE;
            handshake_start_time = 0;
        }
    }
}
