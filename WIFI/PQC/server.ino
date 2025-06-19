/*
 * esp32_tls13_pqc_hybrid_WITH_COMPLETE_HANDSHAKE_METRICS.ino
 * --------------------------------------------------------------------
 * Servidor ESP32 TLS 1.3 + PQC híbrido con métricas COMPLETAS de handshake
 * Base: TLS 1.3 idéntica al código que funciona
 * Añade: Handshake PQC sobre canal TLS establecido
 * Flujo: TLS Handshake → PQC Handshake (sobre TLS) → Datos PQC
 * NOVEDAD: Métricas de handshake TOTAL (TLS + PQC) para comparación justa
 * ------------------------------------------------------------------
 */

#include <WiFi.h>
#include <wolfssl.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/certs_test.h>
#include <wolfssl/wolfcrypt/kyber.h>
#include <wolfssl/wolfcrypt/wc_kyber.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/random.h>

#include "cert_defs.h"          // Material PQC provisionado

/* ---------- CONFIGURACIÓN IDÉNTICA AL TLS QUE FUNCIONA ----------- */
const char* AP_SSID     = "ESP32_AP";
const char* AP_PASSWORD = "esp32password";
const uint16_t TCP_PORT = 12345;

#define TEMP_INTERVAL_MS 1000  // ← Cada 1000ms como TLS puro
#define TLS13_CIPHER_LIST "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"

/* ---------- Constantes PQC ---------------------------------------- */
#define INVALID_DEVID           -1
#define KYBER_PUB_BYTES         800
#define KYBER_CT_BYTES          768
#define KYBER_SS_BYTES           32
#define DILITHIUM_LEVEL          2
#define DILITHIUM_PUB_BYTES   1312
#define DILITHIUM_SIG_BYTES   2420

/* ---------- Simétrico PQC ----------------------------------------- */
#define AES_IV_BYTES             16
#define AES_CT_BYTES             16
#define HMAC_BYTES               32
#define SEC_MSG_BYTES (AES_IV_BYTES + AES_CT_BYTES + HMAC_BYTES)

/* ---------- Duración de clave Kyber antes de re-handshake --------- */
#define KEY_LIFETIME_MS       30000   // 30s

/* ---------- Mensajes PQC sobre TLS -------------------------------- */
enum PQCMsgType : uint8_t {
  PQC_WELCOME       = 0x00,
  PQC_CLI_CERT      = 0x10,
  PQC_SRV_CERT      = 0x11,
  PQC_KYBER_PUB     = 0x30,
  PQC_DILITHIUM_SIG = 0x34,
  PQC_CTX           = 0x31,
  PQC_KYBER_OK      = 0x32,
  PQC_TEMP_SEC      = 0x40
};

/* ============================ MÉTRICAS TCP/IP MEJORADAS ============= */
enum TcpPhase { TCP_PHASE_NONE, TCP_PHASE_TLS_HANDSHAKE, TCP_PHASE_PQC_HANDSHAKE, TCP_PHASE_DATA };
static TcpPhase  currentTcpPhase       = TCP_PHASE_NONE;
static uint32_t  tcp_tx_bytes_phase    = 0;
static uint32_t  tcp_tx_segments_phase = 0;
static uint32_t  tcp_rx_bytes_phase    = 0;

// ============================================================================
// VARIABLES ADICIONALES PARA HANDSHAKE TOTAL (TLS + PQC)
// ============================================================================
static uint32_t total_handshake_tx_bytes = 0;    // Acumula TLS + PQC
static uint32_t total_handshake_rx_bytes = 0;    // Acumula TLS + PQC
static uint32_t tls_handshake_tx_bytes = 0;      // Solo TLS (análisis)
static uint32_t tls_handshake_rx_bytes = 0;      // Solo TLS (análisis)
static uint32_t pqc_handshake_tx_bytes = 0;      // Solo PQC (análisis)
static uint32_t pqc_handshake_rx_bytes = 0;      // Solo PQC (análisis)

// ============ VARIABLES PARA MEMORIA MEJORADA ============
static size_t heap_initial = 0;        // Heap al arranque
static size_t heap_baseline = 0;       // Heap después de inicialización
static size_t heap_max_used = 0;       // Máximo heap usado en la sesión
static size_t stack_total_size = 8192; // Tamaño típico del stack en ESP32 Arduino
static size_t heap_min = SIZE_MAX;     // Mínimo heap libre durante sesión

// ============ ESTRUCTURA PARA SNAPSHOTS DE MEMORIA ============
struct MemorySnapshot {
  size_t heap_free;
  size_t heap_used;
  size_t stack_used;
  unsigned long timestamp;
};

// ============================================================================
// FUNCIÓN DE ACUMULACIÓN Y RESET DE FASE CON MÉTRICAS COMPLETAS
// ============================================================================
void tcp_reset_phase_with_accumulation(TcpPhase p) {
    // Acumular bytes de fase anterior antes de resetear
    if (currentTcpPhase == TCP_PHASE_TLS_HANDSHAKE) {
        total_handshake_tx_bytes += tcp_tx_bytes_phase;  // Sumar TLS
        total_handshake_rx_bytes += tcp_rx_bytes_phase;
        tls_handshake_tx_bytes = tcp_tx_bytes_phase;     // Guardar TLS solo
        tls_handshake_rx_bytes = tcp_rx_bytes_phase;
        Serial.printf(">> TLS Handshake: %u TX, %u RX bytes\n", tcp_tx_bytes_phase, tcp_rx_bytes_phase);
    }
    else if (currentTcpPhase == TCP_PHASE_PQC_HANDSHAKE) {
        total_handshake_tx_bytes += tcp_tx_bytes_phase;  // Sumar PQC
        total_handshake_rx_bytes += tcp_rx_bytes_phase;
        pqc_handshake_tx_bytes = tcp_tx_bytes_phase;     // Guardar PQC solo
        pqc_handshake_rx_bytes = tcp_rx_bytes_phase;
        Serial.printf(">> PQC Handshake: %u TX, %u RX bytes\n", tcp_tx_bytes_phase, tcp_rx_bytes_phase);
        
        // Al completar PQC, tenemos el handshake total completo
        log_complete_handshake_metrics();
    }
    
    // Resetear contadores de fase actual
    currentTcpPhase         = p;
    tcp_tx_bytes_phase      = 0;
    tcp_tx_segments_phase   = 0;
    tcp_rx_bytes_phase      = 0;
}

// Función original para compatibilidad (ahora llama a la nueva)
void tcp_reset_phase(TcpPhase p) {
    tcp_reset_phase_with_accumulation(p);
}

// ============================================================================
// FUNCIÓN PARA GENERAR MÉTRICAS COMPLETAS DE HANDSHAKE
// ============================================================================
void log_complete_handshake_metrics() {
    //  MÉTRICAS PRINCIPALES: HANDSHAKE TOTAL (PARA COMPARACIÓN JUSTA) 
    log_metric("TCP_TLS13_PQC_HYBRID_Total_Handshake", total_handshake_tx_bytes, "bytes_TX");
    log_metric("TCP_TLS13_PQC_HYBRID_Total_Handshake", total_handshake_rx_bytes, "bytes_RX");
    log_metric("TCP_TLS13_PQC_HYBRID_Total_Handshake", total_handshake_tx_bytes + total_handshake_rx_bytes, "bytes_Total");
    
    // ANÁLISIS DETALLADO: COMPONENTES POR SEPARADO 
    log_metric("TCP_TLS13_Portion_Bytes", tls_handshake_tx_bytes, "bytes_TX");
    log_metric("TCP_TLS13_Portion_Bytes", tls_handshake_rx_bytes, "bytes_RX");
    log_metric("TCP_TLS13_Portion_Bytes", tls_handshake_tx_bytes + tls_handshake_rx_bytes, "bytes_Total");
    
    log_metric("TCP_PQC_Portion_Bytes", pqc_handshake_tx_bytes, "bytes_TX");
    log_metric("TCP_PQC_Portion_Bytes", pqc_handshake_rx_bytes, "bytes_RX");
    log_metric("TCP_PQC_Portion_Bytes", pqc_handshake_tx_bytes + pqc_handshake_rx_bytes, "bytes_Total");
    
    //  ANÁLISIS DE CONTRIBUCIÓN (PORCENTAJES) 
    uint32_t total_bytes = total_handshake_tx_bytes + total_handshake_rx_bytes;
    uint32_t tls_total = tls_handshake_tx_bytes + tls_handshake_rx_bytes;
    uint32_t pqc_total = pqc_handshake_tx_bytes + pqc_handshake_rx_bytes;
    
    if (total_bytes > 0) {
        uint32_t tls_percent = (tls_total * 10000) / total_bytes;  // x100 para 2 decimales
        uint32_t pqc_percent = (pqc_total * 10000) / total_bytes;  // x100 para 2 decimales
        
        log_metric("TLS13_Contribution_Percent", tls_percent, "percent_x100");
        log_metric("PQC_Contribution_Percent", pqc_percent, "percent_x100");
        
        // Overhead PQC sobre TLS puro
        if (tls_total > 0) {
            uint32_t pqc_overhead = (pqc_total * 10000) / tls_total;  // x100 para 2 decimales
            log_metric("PQC_Overhead_Over_TLS13", pqc_overhead, "percent_x100");
        }
    }
    
    Serial.printf(">> HANDSHAKE COMPLETO: %u bytes total (%u TLS + %u PQC)\n", 
                  total_bytes, tls_total, pqc_total);
}

void tcp_count_tx(size_t len) {
    if (currentTcpPhase == TCP_PHASE_NONE) return;
    tcp_tx_bytes_phase    += len;
    tcp_tx_segments_phase += 1;
}

void tcp_count_rx(size_t len) {
    if (currentTcpPhase == TCP_PHASE_NONE) return;
    tcp_rx_bytes_phase += len;
}

void tcp_flush_phase_metrics(const char* tag) {
    if (currentTcpPhase == TCP_PHASE_NONE &&
        tcp_tx_bytes_phase == 0 &&
        tcp_rx_bytes_phase == 0 &&
        tcp_tx_segments_phase == 0) {
        return;
    }
    log_metric(tag, tcp_tx_bytes_phase,    "bytes_TX");
    log_metric(tag, tcp_tx_segments_phase, "segments_TX");
    log_metric(tag, tcp_rx_bytes_phase,    "bytes_RX");
}

/* ============================ MÉTRICAS GENERALES =================== */
void log_metric(const char* name, unsigned long value, const char* unit) {
    Serial.printf("[METRIC_WIFI_TLS13_PQC_HYBRID], %s, %lu, %s\n", name, value, unit);
}

// ============ FUNCIONES DE MEMORIA MEJORADAS ============

static MemorySnapshot take_memory_snapshot() {
  MemorySnapshot snap;
  snap.heap_free = esp_get_free_heap_size();
  snap.heap_used = heap_initial - snap.heap_free;
  snap.stack_used = stack_total_size - uxTaskGetStackHighWaterMark(NULL);
  snap.timestamp = micros();
  return snap;
}

static void log_operation_memory_cost(const char* operation, 
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

// FUNCIÓN MEJORADA DE TRACKING DE MEMORIA
static void enhanced_memory_tracking(const char* checkpoint) {
  size_t heap_free = esp_get_free_heap_size();
  size_t heap_used = heap_initial - heap_free;
  size_t stack_free = uxTaskGetStackHighWaterMark(NULL);
  size_t stack_used = stack_total_size - stack_free;
  
  // Actualizar mínimos y máximos
  if (heap_free < heap_min) {
    heap_min = heap_free;
  }
  if (heap_used > heap_max_used) {
    heap_max_used = heap_used;
  }
  
  // Log métricas corregidas
  char metric_name[64];
  snprintf(metric_name, sizeof(metric_name), "Heap_Used_%s", checkpoint);
  log_metric(metric_name, heap_used, "bytes");
  
  snprintf(metric_name, sizeof(metric_name), "Stack_Used_%s", checkpoint);
  log_metric(metric_name, stack_used, "bytes");
  
  // Fragmentación (CRÍTICO para TFM)
  size_t largest_block = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
  float fragmentation = (heap_free > 0) ? 
    (100.0f - (largest_block * 100.0f / heap_free)) : 0;
  
  snprintf(metric_name, sizeof(metric_name), "Heap_Fragmentation_%s", checkpoint);
  log_metric(metric_name, (unsigned long)(fragmentation * 100), "percent_x100");
}

// INICIALIZACIÓN DE BASELINE DE MEMORIA
void init_memory_baseline() {
  heap_initial = esp_get_free_heap_size();
  // stack_total_size ya está inicializado a 8192 (típico para ESP32)
  
  log_metric("Memory_Heap_Initial", heap_initial, "bytes");
  log_metric("Memory_Stack_Total", stack_total_size, "bytes");
}

void set_memory_baseline() {
  heap_baseline = esp_get_free_heap_size();
  size_t wolfssl_overhead = heap_initial - heap_baseline;
  log_metric("WolfSSL_TLS13_PQC_Memory_Overhead", wolfssl_overhead, "bytes");
  log_metric("Memory_Baseline_Heap", heap_baseline, "bytes");
}

// MÉTRICAS FINALES DE SESIÓN
void log_session_memory_summary() {
  log_metric("Session_Heap_Peak_Used", heap_max_used, "bytes");
  log_metric("Session_Heap_Min_Free", heap_min, "bytes");
  
  size_t final_heap = esp_get_free_heap_size();
  long net_consumed = (long)heap_initial - (long)final_heap;
  log_metric("Session_Net_Heap_Consumed", abs(net_consumed), 
             net_consumed >= 0 ? "bytes_consumed" : "bytes_leaked");
}

// Memoria estática y flash
extern uint8_t _bss_start, _bss_end, _data_start, _data_end;
void log_static_ram() {
    size_t bss  = (size_t)&_bss_end   - (size_t)&_bss_start;
    size_t data = (size_t)&_data_end  - (size_t)&_data_start;
    log_metric("Static_BSS_Section",  bss,  "bytes");
    log_metric("Static_DATA_Section", data, "bytes");
}

void log_flash_app_size() {
    size_t used = ESP.getSketchSize();
    size_t free = ESP.getFreeSketchSpace();
    log_metric("Flash_Sketch_Used", used, "bytes");
    log_metric("Flash_Sketch_Free", free, "bytes");
}

/* ---------- Variables globales ------------------------------------- */
WiFiServer server(TCP_PORT);
WiFiClient client;

// TLS (BASE IDÉNTICA AL CÓDIGO QUE FUNCIONA)
static WOLFSSL_CTX* ctx = NULL;
static WOLFSSL* ssl = NULL;

// PQC globals (IDÉNTICOS AL ORIGINAL)
WC_RNG       rng;
dilithium_key caDilKey;
dilithium_key srvDilKey;
uint8_t       srvPub[DILITHIUM_PUB_BYTES];
KyberKey kyberKey;
uint8_t  kyberPub[KYBER_PUB_BYTES];
uint8_t  sessionKey[KYBER_SS_BYTES];
bool     sessionKeySet = false;
uint8_t dilithiumSig[DILITHIUM_SIG_BYTES];
word32  sigLen = DILITHIUM_SIG_BYTES;
uint8_t clientPubKey[DILITHIUM_PUB_BYTES];

// Variables para medir handshake
static unsigned long t_tcp_handshake_in = 0;
static unsigned long t_tls_handshake_complete = 0;
static unsigned long t_pqc_handshake_complete = 0;
static unsigned long t_lastTemp = 0;

// Estados de sesión
static bool tlsSessionActive = false;
static bool pqcSessionActive = false;

float current_temperature = 25.0;

/* ================ I/O CALLBACKS (IDÉNTICOS AL TLS QUE FUNCIONA) === */
static int EthernetSend(WOLFSSL* ssl, char* message, int sz, void* ctx) {
    (void)ssl; (void)ctx;
    if (!client.connected()) return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    
    size_t written = client.write((byte*)message, sz);
    
    if (currentTcpPhase != TCP_PHASE_NONE && written > 0) {
        tcp_count_tx(written);
    }
    
    return written;
}

static int EthernetReceive(WOLFSSL* ssl, char* reply, int sz, void* ctx) {
    int ret = 0;
    (void)ssl; (void)ctx;
    
    if (!client.connected()) return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    
    while (client.available() > 0 && ret < sz) {
        reply[ret++] = client.read();
    }
    
    if (currentTcpPhase != TCP_PHASE_NONE && ret > 0) {
        tcp_count_rx(ret);
    }
    
    return ret;
}

/* ================ PQC FRAMING OVER TLS ============================ */
const char* pqcMsgTypeName(PQCMsgType t) {
  switch(t) {
    case PQC_WELCOME:       return "PQC_Bienvenida";
    case PQC_CLI_CERT:      return "PQC_Certificado_Cliente";
    case PQC_SRV_CERT:      return "PQC_Certificado_Servidor";
    case PQC_KYBER_PUB:     return "PQC_Clave_Publica_Kyber";
    case PQC_DILITHIUM_SIG: return "PQC_Firma_Dilithium";
    case PQC_CTX:           return "PQC_Ciphertext_Kyber";
    case PQC_KYBER_OK:      return "PQC_Confirmacion_Kyber";
    case PQC_TEMP_SEC:      return "PQC_Temperatura_Cifrada";
    default:                return "PQC_Desconocido";
  }
}

bool sendPQCFrame(PQCMsgType t, const uint8_t* payload_ptr=nullptr, uint16_t payload_len=0) {
  if (!ssl || !tlsSessionActive) return false;
  
  if (t != PQC_TEMP_SEC) {
    Serial.printf("\n>> Enviando frame PQC sobre TLS: %s (payload %u bytes)\n", pqcMsgTypeName(t), payload_len);
  }
  
  uint8_t hdr[3] = { static_cast<uint8_t>(t), static_cast<uint8_t>(payload_len >> 8), static_cast<uint8_t>(payload_len & 0xFF) };
  
  // Enviar header por TLS
  if (wolfSSL_write(ssl, hdr, 3) != 3) {
    Serial.println("!! Error enviando header PQC por TLS");
    return false;
  }
  
  // Enviar payload si existe
  if (payload_len > 0) {
    if (wolfSSL_write(ssl, payload_ptr, payload_len) != payload_len) {
      Serial.println("!! Error enviando payload PQC por TLS");
      return false;
    }
  }
  
  return true;
}

bool recvPQCExact(uint8_t* dst, size_t len, uint32_t tout=3000) {
  size_t n=0; uint32_t t0=millis();
  while(n<len && millis()-t0<tout) {
    if(!client.connected() || !tlsSessionActive) return false;
    
    int bytes_read = wolfSSL_read(ssl, dst+n, len-n);
    if (bytes_read > 0) {
        n += bytes_read;
    } else if (bytes_read < 0) {
        int error = wolfSSL_get_error(ssl, bytes_read);
        if (error != WOLFSSL_ERROR_WANT_READ && error != WOLFSSL_ERROR_WANT_WRITE) {
            return false;
        }
    }
    delay(1);
  }
  return n==len;
}

/* ================ PQC INITIALIZATION (MÉTRICAS AÑADIDAS) ========== */
bool initCA() {
  MemorySnapshot before_ca = take_memory_snapshot();
  enhanced_memory_tracking("Before_CA_Init");
  
  wc_dilithium_init(&caDilKey);
  wc_dilithium_set_level(&caDilKey, DILITHIUM_LEVEL);
  int ret_import = wc_dilithium_import_public(CA_PUB, CA_PUB_LEN, &caDilKey);
  
  MemorySnapshot after_ca = take_memory_snapshot();
  enhanced_memory_tracking("After_CA_Init");
  log_operation_memory_cost("PQC_CA_Init", before_ca, after_ca);
  
  if (ret_import != 0) {
    Serial.print("ERROR: import CA_PUB, err_code="); Serial.println(ret_import);
    return false;
  }
  return true;
}

bool initServerDil() {
  MemorySnapshot before_srv = take_memory_snapshot();
  enhanced_memory_tracking("Before_Server_Dilithium_Init");
  
  int ret_val = wc_dilithium_init_ex(&srvDilKey, NULL, INVALID_DEVID);
  if (ret_val != 0) {
    Serial.print("ERROR: dilithium_init_ex for srvDilKey, err_code="); Serial.println(ret_val);
    return false;
  }
  wc_dilithium_set_level(&srvDilKey, DILITHIUM_LEVEL);
  
  ret_val = wc_dilithium_import_private(SRV_PRIV, SRV_PRIV_LEN, &srvDilKey);
  if (ret_val != 0) {
    Serial.print("ERROR: import srv_priv, err_code="); Serial.println(ret_val);
    return false;
  }
  
  if (CERT_BODY_SIZE < DILITHIUM_PUB_BYTES) {
    Serial.println("ERROR: CERT_BODY_SIZE < DILITHIUM_PUB_BYTES");
    return false;
  }
  size_t offset_srv_pub = CERT_BODY_SIZE - DILITHIUM_PUB_BYTES;
  memcpy(srvPub, SRV_CERT + offset_srv_pub, DILITHIUM_PUB_BYTES);
  
  MemorySnapshot after_srv = take_memory_snapshot();
  enhanced_memory_tracking("After_Server_Dilithium_Init");
  log_operation_memory_cost("PQC_Server_Dilithium_Init", before_srv, after_srv);
  
  Serial.printf(">> srvPub extraída de SRV_CERT en offset %u\n", (unsigned)offset_srv_pub);
  return true;
}

bool verifyClientCertAndExtractPub(const uint8_t* cert_data, size_t cert_len) {
  if (cert_data == nullptr || cert_len == 0) return false;
  if (cert_len < CERT_BODY_SIZE) {
    Serial.println("ERROR: Longitud del certificado del cliente insuficiente para el cuerpo.");
    return false;
  }
  
  const word32 msgSz = CERT_BODY_SIZE;
  const word32 sigSz = cert_len - msgSz;

  if (sigSz <= 0 || sigSz > DILITHIUM_SIG_BYTES) {
      Serial.printf("ERROR: Longitud de firma del cert cliente inválida (%u).\n", (unsigned)sigSz);
      return false;
  }

  MemorySnapshot before_verify = take_memory_snapshot();
  enhanced_memory_tracking("Before_Dilithium_Verify");

  long start_v = micros();
  int vr=0;
  int ret_verify = wc_dilithium_verify_msg(
      cert_data + msgSz, sigSz,
      cert_data,         msgSz,
      &vr, &caDilKey);
  long end_v = micros();
  
  MemorySnapshot after_verify = take_memory_snapshot();
  enhanced_memory_tracking("After_Dilithium_Verify");
  log_operation_memory_cost("Dilithium_Verify", before_verify, after_verify);
  
  log_metric("Dilithium_Verify_ClientCert", end_v - start_v, "us");
  
  if (ret_verify != 0 || vr != 1) {
    Serial.printf("ERROR: Fallo verificación certificado cliente (ret=%d, verify_result=%d)\n", ret_verify, vr);
    return false;
  }
  
  size_t offset_cli_pub = CERT_BODY_SIZE - DILITHIUM_PUB_BYTES;
  memcpy(clientPubKey, cert_data + offset_cli_pub, DILITHIUM_PUB_BYTES);
  
  Serial.println(">> Certificado del cliente verificado y clave pública extraída OK.");
  return true;
}

void sendKyberHandshake() {
  if (sessionKeySet) {
    Serial.println(">> Re-handshake Kyber solicitado.");
  }
  
  MemorySnapshot before_keygen = take_memory_snapshot();
  enhanced_memory_tracking("Before_Kyber_KeyGen");
  
  long t0 = micros();
  int ret_init_ky = wc_KyberKey_Init(WC_ML_KEM_512, &kyberKey, NULL, INVALID_DEVID);
  if (ret_init_ky != 0) {
    Serial.print("Error en wc_KyberKey_Init: "); Serial.println(ret_init_ky); return;
  }
  int ret_make_ky = wc_KyberKey_MakeKey(&kyberKey, &rng);
  if (ret_make_ky != 0) {
    Serial.print("Error en wc_KyberKey_MakeKey: "); Serial.println(ret_make_ky); return;
  }
  long t1 = micros();
  
  MemorySnapshot after_keygen = take_memory_snapshot();
  enhanced_memory_tracking("After_Kyber_KeyGen");
  log_operation_memory_cost("Kyber_KeyGen", before_keygen, after_keygen);
  
  log_metric("Kyber_KeyGen", t1 - t0, "us");

  int ret_enc_pub = wc_KyberKey_EncodePublicKey(&kyberKey, kyberPub, KYBER_PUB_BYTES);
  if (ret_enc_pub != 0) {
    Serial.print("Error en wc_KyberKey_EncodePublicKey: "); Serial.println(ret_enc_pub); return;
  }

  sigLen = DILITHIUM_SIG_BYTES;
  
  MemorySnapshot before_sign = take_memory_snapshot();
  enhanced_memory_tracking("Before_Dilithium_Sign");
  
  long t2 = micros();
  int ret_sign = wc_dilithium_sign_msg(
    kyberPub, KYBER_PUB_BYTES,
    dilithiumSig, &sigLen,
    &srvDilKey, &rng
  );
  long t3 = micros();
  
  MemorySnapshot after_sign = take_memory_snapshot();
  enhanced_memory_tracking("After_Dilithium_Sign");
  log_operation_memory_cost("Dilithium_Sign", before_sign, after_sign);
  
  if (ret_sign != 0) {
    Serial.print("Error en wc_dilithium_sign_msg: "); Serial.println(ret_sign); return;
  }
  log_metric("Dilithium_Sign_KyberPub", t3 - t2, "us");

  enhanced_memory_tracking("PQC_Handshake_Generated");

  // Envío de la clave pública Kyber y su firma Dilithium POR TLS
  sendPQCFrame(PQC_KYBER_PUB,     kyberPub,     KYBER_PUB_BYTES);
  sendPQCFrame(PQC_DILITHIUM_SIG, dilithiumSig, sigLen);

  sessionKeySet = false;
  Serial.println(">> Handshake PQC (Pub Kyber + Sig Dilithium) enviado sobre TLS.");
}

void aesCbcHmac(const char* msg, uint8_t out_iv[AES_IV_BYTES], uint8_t out_ct[AES_CT_BYTES], uint8_t out_hmac[HMAC_BYTES], bool detailed_metrics = false) {
  MemorySnapshot before_aes, after_aes;
  if (detailed_metrics) {
    before_aes = take_memory_snapshot();
    enhanced_memory_tracking("Before_AES_HMAC");
  }
  
  long t0_aes_hmac = micros();
  
  Aes aes; 
  int ret_aes_init = wc_AesInit(&aes, NULL, INVALID_DEVID);
  if (ret_aes_init != 0) { Serial.print("AES Init Error: "); Serial.println(ret_aes_init); return; }

  int ret_rng_iv = wc_RNG_GenerateBlock(&rng, out_iv, AES_IV_BYTES);
  if (ret_rng_iv != 0) { Serial.print("AES IV Gen Error: "); Serial.println(ret_rng_iv); wc_AesFree(&aes); return; }
  
  int ret_aes_key = wc_AesSetKey(&aes, sessionKey, KYBER_SS_BYTES, out_iv, AES_ENCRYPTION);
  if (ret_aes_key != 0) { Serial.print("AES SetKey Error: "); Serial.println(ret_aes_key); wc_AesFree(&aes); return; }

  size_t msg_len = strlen(msg);
  size_t padded_len = ((msg_len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE; 
  if (padded_len > AES_CT_BYTES) {
      Serial.printf("Error: Mensaje con padding (%u) demasiado grande para buffer AES_CT_BYTES (%d)\n", (unsigned)padded_len, AES_CT_BYTES);
      wc_AesFree(&aes);
      return;
  }

  uint8_t padded_msg_buf[AES_CT_BYTES] = {0};
  memcpy(padded_msg_buf, msg, msg_len);
  uint8_t pad_val = padded_len - msg_len;
  memset(padded_msg_buf + msg_len, pad_val, pad_val);

  int ret_aes_enc = wc_AesCbcEncrypt(&aes, out_ct, padded_msg_buf, padded_len);
  wc_AesFree(&aes);
  if (ret_aes_enc != 0) { Serial.print("AES Encrypt Error: "); Serial.println(ret_aes_enc); return; }

  Hmac hmac_ctx; 
  int ret_hmac_init = wc_HmacInit(&hmac_ctx, NULL, INVALID_DEVID);
  if (ret_hmac_init != 0) { Serial.print("HMAC Init Error: "); Serial.println(ret_hmac_init); return; }

  int ret_hmac_key = wc_HmacSetKey(&hmac_ctx, WC_SHA256, sessionKey, KYBER_SS_BYTES);
  if (ret_hmac_key != 0) { Serial.print("HMAC SetKey Error: "); Serial.println(ret_hmac_key); wc_HmacFree(&hmac_ctx); return; }
  
  wc_HmacUpdate(&hmac_ctx, out_iv, AES_IV_BYTES);
  wc_HmacUpdate(&hmac_ctx, out_ct, padded_len);
  
  int ret_hmac_final = wc_HmacFinal(&hmac_ctx, out_hmac);
  wc_HmacFree(&hmac_ctx);
  if (ret_hmac_final != 0) { Serial.print("HMAC Final Error: "); Serial.println(ret_hmac_final); return; }

  long t1_aes_hmac = micros();
  
  if (detailed_metrics) {
    after_aes = take_memory_snapshot();
    enhanced_memory_tracking("After_AES_HMAC");
    log_operation_memory_cost("AES_HMAC", before_aes, after_aes);
  }
  
  log_metric("AES_HMAC_Operation", t1_aes_hmac - t0_aes_hmac, "us");
}

/* ================ SETUP FUNCTIONS (BASE TLS + MÉTRICAS) =========== */
int setup_network(void) {
    // CONFIGURACIÓN IDÉNTICA AL CÓDIGO TLS QUE FUNCIONA
    WiFi.softAP(AP_SSID, AP_PASSWORD);
    delay(2000);
    Serial.printf("AP \"%s\" listo. IP: %s, Puerto: %d\n",
                  AP_SSID, WiFi.softAPIP().toString().c_str(), TCP_PORT);
    return 0;
}

int setup_wolfssl(void) {
    MemorySnapshot before_wolfssl = take_memory_snapshot();
    enhanced_memory_tracking("Before_WolfSSL_Init");
    
    long t0 = micros();
    
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        Serial.println("wolfSSL_Init failed");
        return -1;
    }
    
    // *** TLS 1.3 IDÉNTICO AL CÓDIGO QUE FUNCIONA ***
    WOLFSSL_METHOD* method = wolfTLSv1_3_server_method();
    if (method == NULL) {
        Serial.println("TLS 1.3 method failed - fallback to TLS 1.2");
        method = wolfTLSv1_3_server_method();
        if (method == NULL) return -1;
    }
    
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) return -1;
    
    // Configuración específica de TLS 1.3
    if (wolfSSL_CTX_set_cipher_list(ctx, TLS13_CIPHER_LIST) != WOLFSSL_SUCCESS) {
        Serial.println("Warning: TLS 1.3 cipher list failed, using defaults");
    }
    
    long t1 = micros();
    
    MemorySnapshot after_wolfssl = take_memory_snapshot();
    enhanced_memory_tracking("After_WolfSSL_Init");
    log_operation_memory_cost("WolfSSL_TLS13_Init", before_wolfssl, after_wolfssl);
    
    log_metric("TLS13_Context_Init", t1 - t0, "us");
    
    // ESTABLECER BASELINE DESPUÉS DE WOLFSSL (pero antes de PQC)
    set_memory_baseline();
    
    return 0;
}

int setup_certificates(void) {
    MemorySnapshot before_certs = take_memory_snapshot();
    enhanced_memory_tracking("Before_TLS_Cert_Load");
    
    long t0 = micros();
    
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
    wolfSSL_CTX_use_certificate_buffer(ctx, CTX_SERVER_CERT, CTX_SERVER_CERT_SIZE, CTX_CA_CERT_TYPE);
    wolfSSL_CTX_use_PrivateKey_buffer(ctx, CTX_SERVER_KEY, CTX_SERVER_KEY_SIZE, CTX_SERVER_KEY_TYPE);
    
    long t1 = micros();
    
    MemorySnapshot after_certs = take_memory_snapshot();
    enhanced_memory_tracking("After_TLS_Cert_Load");
    log_operation_memory_cost("TLS13_Certificates_Load", before_certs, after_certs);
    
    log_metric("TLS13_Certificates_Load", t1 - t0, "us");
    return 0;
}

/* ================ TLS HANDSHAKE HANDLER (MÉTRICAS AÑADIDAS) ======= */
void handle_tls_handshake() {
    MemorySnapshot before_handshake = take_memory_snapshot();
    enhanced_memory_tracking("Before_TLS13_Handshake");
    
    long t0_handshake = micros();
    
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        Serial.println("Error: wolfSSL_new falló");
        return;
    }
    
    if (wolfSSL_accept(ssl) != WOLFSSL_SUCCESS) {
        int error = wolfSSL_get_error(ssl, 0);
        Serial.printf("TLS 1.3 handshake falló. Error: %d\n", error);
        wolfSSL_free(ssl);
        ssl = NULL;
        return;
    }
    
    long t1_handshake = micros();
    
    MemorySnapshot after_handshake = take_memory_snapshot();
    enhanced_memory_tracking("After_TLS13_Handshake");
    log_operation_memory_cost("TLS13_Handshake", before_handshake, after_handshake);
    
    t_tls_handshake_complete = millis();
    unsigned long tiempo_tls = t_tls_handshake_complete - t_tcp_handshake_in;
    
    log_metric("TLS13_Handshake_Time", t1_handshake - t0_handshake, "us");
    log_metric("WiFi_TLS13_Handshake_Latency", tiempo_tls, "ms");
    
    const char* version = wolfSSL_get_version(ssl);
    const char* cipher = wolfSSL_get_cipher(ssl);
    Serial.printf("TLS OK - Version: %s, Cipher: %s\n", version, cipher);
    
    if (wolfSSL_GetVersion(ssl) == WOLFSSL_TLSV1_3) {
        log_metric("TLS13_Negotiated", 1, "boolean");
        Serial.println(">> TLS 1.3 negociado exitosamente");
    } else {
        log_metric("TLS13_Negotiated", 0, "boolean");
        Serial.printf(">> Protocolo negociado: %s (no TLS 1.3)\n", version);
    }
    
    // TLS handshake completado - CAMBIAR A FASE PQC CON ACUMULACIÓN
    if (currentTcpPhase == TCP_PHASE_TLS_HANDSHAKE) {
        tcp_flush_phase_metrics("TCP_TLS13_Handshake_Complete");
        tcp_reset_phase_with_accumulation(TCP_PHASE_PQC_HANDSHAKE);  // *** CAMBIO CLAVE ***
        tlsSessionActive = true;
        Serial.println(">> TLS 1.3 establecido. Iniciando handshake PQC sobre TLS...");
        
        // Iniciar handshake PQC sobre TLS
        sendPQCFrame(PQC_WELCOME, (const uint8_t*)"PQC_Ready", 9);
    }
}

/* ================ ARDUINO SETUP =================================== */
void setup(void) {
    Serial.begin(115200);
    unsigned long boot_wait_start = millis();
    while(!Serial && (millis() - boot_wait_start < 3000)) delay(100);
    
    Serial.println("\n\n--- ESP32 TLS 1.3 + PQC HÍBRIDO Server con Métricas de Handshake COMPLETO ---");
    Serial.printf("Free heap: %d bytes\n", ESP.getFreeHeap());
    
    randomSeed(analogRead(0));
    
    // INICIALIZAR BASELINE DE MEMORIA
    init_memory_baseline();
    
    // Métricas Flash/RAM iniciales
    log_flash_app_size();
    log_static_ram();
    enhanced_memory_tracking("Initial_Setup");
    
    if (setup_network() != 0) {
        Serial.println("Network setup failed");
        while(1) delay(1000);
    }
    
    if (setup_wolfssl() != 0) {
        Serial.println("wolfSSL TLS 1.3 setup failed");
        while(1) delay(1000);
    }
    
    if (setup_certificates() != 0) {
        Serial.println("Certificates setup failed");
        while(1) delay(1000);
    }
    
    // INICIALIZAR PQC (DESPUÉS DE TLS, CON MÉTRICAS)
    MemorySnapshot before_pqc_init = take_memory_snapshot();
    enhanced_memory_tracking("Before_PQC_Init");
    
    int ret_val = wc_InitRng(&rng);
    if (ret_val != 0) { 
        Serial.print("FATAL: wc_InitRng falló, err_code="); Serial.println(ret_val); 
        while(1) delay(1000);
    }
    
    if (!initCA()) { Serial.println("FATAL: initCA falló."); while(1) delay(1000); }
    if (!initServerDil()) { Serial.println("FATAL: initServerDil falló."); while(1) delay(1000); }
    
    MemorySnapshot after_pqc_init = take_memory_snapshot();
    enhanced_memory_tracking("After_PQC_Init");
    log_operation_memory_cost("PQC_Full_Init", before_pqc_init, after_pqc_init);
    
    Serial.println(">> PQC inicializado correctamente");
    
    wolfSSL_SetIOSend(ctx, EthernetSend);
    wolfSSL_SetIORecv(ctx, EthernetReceive);
    
    server.begin();
    
    Serial.printf("TLS 1.3 + PQC HÍBRIDO Server ready on %s:%d\n", WiFi.softAPIP().toString().c_str(), TCP_PORT);
    Serial.println("--- Setup Completado. Esperando clientes... ---");
    
    enhanced_memory_tracking("Complete_Setup");
}

/* ================ MAIN LOOP ======================================= */
void loop() {
    // GESTIÓN DE CONEXIÓN (IDÉNTICA AL TLS QUE FUNCIONA + MÉTRICAS)
    if (!client || !client.connected()) {
        if (client) {
            Serial.println("<< Cliente anterior desconectado.");
            client.stop();
            tlsSessionActive = false;
            pqcSessionActive = false;
            sessionKeySet = false;
            if (ssl) {
                wolfSSL_shutdown(ssl);
                wolfSSL_free(ssl);
                ssl = NULL;
            }
            log_metric("Session_Ended_By_Disconnect", millis(), "ms");
            
            // Métricas finales de sesión
            log_session_memory_summary();

            if (currentTcpPhase == TCP_PHASE_DATA) {
                tcp_flush_phase_metrics("TCP_Data_Total_OnDisconnect");
            } else if (currentTcpPhase == TCP_PHASE_PQC_HANDSHAKE) {
                tcp_flush_phase_metrics("TCP_PQC_Handshake_Incomplete_OnDisconnect");
            } else if (currentTcpPhase == TCP_PHASE_TLS_HANDSHAKE) {
                tcp_flush_phase_metrics("TCP_TLS_Handshake_Incomplete_OnDisconnect");
            }
            tcp_reset_phase(TCP_PHASE_NONE);
            
            // RESETEAR VARIABLES DE HANDSHAKE COMPLETO 
            total_handshake_tx_bytes = 0;
            total_handshake_rx_bytes = 0;
            tls_handshake_tx_bytes = 0;
            tls_handshake_rx_bytes = 0;
            pqc_handshake_tx_bytes = 0;
            pqc_handshake_rx_bytes = 0;
        }

        client = server.available();
        if (!client) {
            delay(100);
            return;
        }

        // NUEVO CLIENTE - EXACTAMENTE IGUAL QUE TLS QUE FUNCIONA
        t_tcp_handshake_in = millis();
        Serial.printf(">> Nuevo cliente conectado: %s (TLS 1.3 handshake empezará ahora)\n",
                      client.remoteIP().toString().c_str());

        tcp_reset_phase(TCP_PHASE_TLS_HANDSHAKE);
        
        // Resetear métricas de sesión
        heap_min = SIZE_MAX;
        heap_max_used = 0;
        enhanced_memory_tracking("Connection_Start");
        
        handle_tls_handshake();
        return;
    }

    // PROCESAMIENTO DE MENSAJES PQC SOBRE TLS
    if (tlsSessionActive && !pqcSessionActive) {
        // Leer frames PQC a través del canal TLS
        if (wolfSSL_pending(ssl) > 0 || client.available() > 0) {
            uint8_t hdr[3];
            if (!recvPQCExact(hdr, 3)) {
                Serial.println("!! Error leyendo header PQC sobre TLS");
                client.stop();
                return;
            }

            uint16_t payload_len = (static_cast<uint16_t>(hdr[1]) << 8) | hdr[2];
            PQCMsgType msg_type = static_cast<PQCMsgType>(hdr[0]);
            Serial.printf("<< Frame PQC sobre TLS: %s (0x%02X), Longitud: %u bytes\n",
                          pqcMsgTypeName(msg_type), hdr[0], payload_len);

            switch (msg_type) {
                case PQC_CLI_CERT: {
                    if (payload_len != CLI_CERT_LEN) {
                        Serial.printf("!! Error: Longitud de PQC_CLI_CERT incorrecta (esperado %d, recibido %u)\n",
                                      CLI_CERT_LEN, payload_len);
                        client.stop();
                        break;
                    }
                    uint8_t cli_cert_buf[CLI_CERT_LEN];
                    if (!recvPQCExact(cli_cert_buf, payload_len)) {
                        Serial.println("!! Error leyendo payload de PQC_CLI_CERT");
                        client.stop();
                        break;
                    }
                    
                    if (!verifyClientCertAndExtractPub(cli_cert_buf, payload_len)) {
                        Serial.println("!! Falló la verificación del certificado PQC del cliente. Desconectando.");
                        client.stop();
                        break;
                    }
                    
                    // Certificado del cliente OK, proceder con el handshake PQC
                    sendPQCFrame(PQC_SRV_CERT, SRV_CERT, SRV_CERT_LEN);
                    sendKyberHandshake();
                    break;
                }
                case PQC_CTX: { // Ciphertext Kyber del cliente
                    if (payload_len != KYBER_CT_BYTES) {
                        Serial.printf("!! Error: Longitud de PQC_CTX incorrecta (esperado %d, recibido %u)\n",
                                      KYBER_CT_BYTES, payload_len);
                        client.stop();
                        break;
                    }
                    uint8_t kyber_ct_buf[KYBER_CT_BYTES];
                    if (!recvPQCExact(kyber_ct_buf, payload_len)) {
                        Serial.println("!! Error leyendo payload de PQC_CTX");
                        client.stop();
                        break;
                    }

                    MemorySnapshot before_decap = take_memory_snapshot();
                    enhanced_memory_tracking("Before_Kyber_Decapsulate");
                    
                    long t0_decap = micros();
                    int rc_decap = wc_KyberKey_Decapsulate(&kyberKey, sessionKey, kyber_ct_buf, payload_len);
                    long t1_decap = micros();
                    
                    MemorySnapshot after_decap = take_memory_snapshot();
                    enhanced_memory_tracking("After_Kyber_Decapsulate");
                    log_operation_memory_cost("Kyber_Decapsulate", before_decap, after_decap);
                    
                    log_metric("Kyber_Decapsulate", t1_decap - t0_decap, "us");

                    if (rc_decap != 0) {
                        Serial.printf("!! Error en Kyber Decapsulate (código %d). Desconectando.\n", rc_decap);
                        client.stop();
                        break;
                    }

                    sessionKeySet = true;
                    pqcSessionActive = true;
                    t_pqc_handshake_complete = millis();
                    
                    enhanced_memory_tracking("PQC_Handshake_Complete");
                    
                    unsigned long tiempo_pqc = t_pqc_handshake_complete - t_tls_handshake_complete;
                    unsigned long tiempo_total = t_pqc_handshake_complete - t_tcp_handshake_in;
                    
                    log_metric("PQC_Handshake_Time", tiempo_pqc, "ms");
                    log_metric("WiFi_TLS13_PQC_Total_Handshake_Latency", tiempo_total, "ms");
                    
                    Serial.println(">> Clave de sesión PQC establecida sobre TLS correctamente.");
                    sendPQCFrame(PQC_KYBER_OK, nullptr, 0);

                    // Cambiar a fase de datos CON ACUMULACIÓN
                    if (currentTcpPhase == TCP_PHASE_PQC_HANDSHAKE) {
                        tcp_flush_phase_metrics("TCP_PQC_Handshake_Complete");
                        tcp_reset_phase_with_accumulation(TCP_PHASE_DATA);  // *** CAMBIO CLAVE ***
                    }
                    break;
                }
                default: {
                    Serial.printf("!! Frame PQC desconocido tipo 0x%02X, descartando %u bytes de payload.\n",
                                  hdr[0], payload_len);
                    uint8_t discard_buffer[64];
                    while (payload_len > 0) {
                        size_t to_discard = min((size_t)payload_len, sizeof(discard_buffer));
                        if (!recvPQCExact(discard_buffer, to_discard)) {
                            Serial.println("!! Error descartando payload desconocido PQC, o cliente desconectado.");
                            client.stop();
                            return;
                        }
                        payload_len -= to_discard;
                    }
                    break;
                }
            }
        }
    }

    // RE-HANDSHAKE PQC cada KEY_LIFETIME_MS (igual que el original)
    if (pqcSessionActive && sessionKeySet && (millis() - t_pqc_handshake_complete >= KEY_LIFETIME_MS)) {
        Serial.println(">> Tiempo de vida de clave PQC expirado. Iniciando re-handshake...");
        log_metric("PQC_Rehandshake_Triggered", millis(), "ms_uptime");
        
        if (currentTcpPhase == TCP_PHASE_DATA) {
            tcp_flush_phase_metrics("TCP_Data_Before_PQC_Rekey");
        }
        tcp_reset_phase(TCP_PHASE_PQC_HANDSHAKE);
        pqcSessionActive = false;
        sendKyberHandshake();
    }

    // ENVÍO DE TEMPERATURA CIFRADA PQC: exactamente 25 notificaciones, cada 1000ms
    static int temp_notif_count = 0;
    if (pqcSessionActive && sessionKeySet && temp_notif_count < 25 && (millis() - t_lastTemp >= TEMP_INTERVAL_MS)) {
        t_lastTemp = millis();
        current_temperature += 0.5;
        if (current_temperature > 35.0) current_temperature = 20.0;

        char temp_text[16];
        snprintf(temp_text, sizeof(temp_text), "%.2fC", current_temperature);

        uint8_t current_iv[AES_IV_BYTES];
        uint8_t current_ct[AES_CT_BYTES];
        uint8_t current_hmac[HMAC_BYTES];

        // Solo métricas detalladas en las primeras 2 temperaturas
        bool show_detailed_metrics = (temp_notif_count < 2);
        aesCbcHmac(temp_text, current_iv, current_ct, current_hmac, show_detailed_metrics);

        // Construir payload: IV + Ciphertext + HMAC
        uint8_t temp_payload[SEC_MSG_BYTES];
        memcpy(temp_payload, current_iv, AES_IV_BYTES);
        memcpy(temp_payload + AES_IV_BYTES, current_ct, AES_CT_BYTES);
        memcpy(temp_payload + AES_IV_BYTES + AES_CT_BYTES, current_hmac, HMAC_BYTES);

        if (sendPQCFrame(PQC_TEMP_SEC, temp_payload, SEC_MSG_BYTES)) {
            temp_notif_count++;
            log_metric("Temp_Notifs_Sent_TLS13_PQC_Hybrid", temp_notif_count, "count");
            
            // Mensaje más conciso - solo detalles en las primeras 2 temperaturas
            if (temp_notif_count <= 2) {
                Serial.printf(">> %.2f°C (msg %d/25) - TLS+PQC HÍBRIDO [con métricas detalladas]\n", current_temperature, temp_notif_count);
            } else if (temp_notif_count % 5 == 0) {
                // Mostrar cada 5 temperaturas para confirmar progreso
                Serial.printf(">> %.2f°C (msg %d/25) - TLS+PQC HÍBRIDO\n", current_temperature, temp_notif_count);
            }
        } else {
            Serial.println("!! Fallo al enviar temperatura cifrada PQC.");
        }

        // Si alcanzamos 25 notificaciones, volcamos métricas finales
        if (temp_notif_count == 25) {
            tcp_flush_phase_metrics("TCP_Data_Total");
            enhanced_memory_tracking("After_25_Notifications");
        }
    }

    // Ceder control si no hay nada más que procesar
    if (!client.available()) {
        delay(10);
    }
}
