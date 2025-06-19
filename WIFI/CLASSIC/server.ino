/*
 * 
 * --------------------------------------------------------------------
 * Servidor ESP32 TLS 1.3 con métricas de memoria  
 * ------------------------------------------------------------------
 */

#include <WiFi.h>
#include <wolfssl.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/certs_test.h>

/* ---------- CONFIGURACIÓN IDÉNTICA AL CÓDIGO QUE FUNCIONA -------- */
const char* AP_SSID     = "ESP32_AP";
const char* AP_PASSWORD = "esp32password";
const uint16_t TCP_PORT = 12345;

#define TEMP_INTERVAL_MS 1000  // ← Cada 1000ms como PQC

/* TLS 1.3 Cipher list optimizado */
#define TLS13_CIPHER_LIST "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"

// ============ NUEVAS VARIABLES GLOBALES PARA MEMORIA MEJORADA ============
static size_t heap_initial = 0;        // Heap al arranque
static size_t heap_baseline = 0;       // Heap después de inicialización
static size_t heap_max_used = 0;       // Máximo heap usado en la sesión
static size_t stack_total_size = 8192; // Tamaño típico del stack en ESP32 Arduino

// ============ ESTRUCTURA PARA SNAPSHOTS DE MEMORIA ============
struct MemorySnapshot {
  size_t heap_free;
  size_t heap_used;
  size_t stack_used;
  unsigned long timestamp;
};

/* ============================ MÉTRICAS TCP/IP ======================= */
enum TcpPhase { TCP_PHASE_NONE, TCP_PHASE_HANDSHAKE, TCP_PHASE_DATA };
static TcpPhase  currentTcpPhase       = TCP_PHASE_NONE;
static uint32_t  tcp_tx_bytes_phase    = 0;
static uint32_t  tcp_tx_segments_phase = 0;
static uint32_t  tcp_rx_bytes_phase    = 0;

void tcp_reset_phase(TcpPhase p) {
    currentTcpPhase         = p;
    tcp_tx_bytes_phase      = 0;
    tcp_tx_segments_phase   = 0;
    tcp_rx_bytes_phase      = 0;
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

// Métrica genérica - formato compatible con análisis comparativo. 

//SI SE QUIERE MOSTAR METRICAS PARA ESTE PROYECTO, DESCOMENTAR 
void log_metric(const char* name, unsigned long value, const char* unit) {
    // Serial.printf("[METRIC_WIFI_TLS13], %s, %lu, %s\n", name, value, unit);
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

// Fragmentación de heap durante ejecución
static size_t heap_min = SIZE_MAX;

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
  
  // Fragmentación
  size_t largest_block = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
  float fragmentation = (heap_free > 0) ? 
    (100.0f - (largest_block * 100.0f / heap_free)) : 0;
  
  snprintf(metric_name, sizeof(metric_name), "Heap_Fragmentation_%s", checkpoint);
  log_metric(metric_name, (unsigned long)(fragmentation * 100), "percent_x100");
}

// INICIALIZACIÓN DE BASELINE DE MEMORIA
void init_memory_baseline() {
  heap_initial = esp_get_free_heap_size();
  
  
  log_metric("Memory_Heap_Initial", heap_initial, "bytes");
  log_metric("Memory_Stack_Total", stack_total_size, "bytes");
}

void set_memory_baseline() {
  heap_baseline = esp_get_free_heap_size();
  size_t wolfssl_overhead = heap_initial - heap_baseline;
  log_metric("WolfSSL_TLS13_Memory_Overhead", wolfssl_overhead, "bytes");
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

static WOLFSSL_CTX* ctx = NULL;
static WOLFSSL* ssl = NULL;

/* Variables para medir handshake */
static unsigned long t_tcp_handshake_in = 0;
static unsigned long t_handshake        = 0;
static unsigned long t_lastTemp         = 0;

/* Control de sesión TLS - equivalente a sessionKeySet en PQC */
static bool tlsSessionActive = false;

/* Simulación de sensor */
float current_temperature = 25.0;

/* ================ SENSOR SIMPLIFICADO ============================= */
float read_temperature() {
    static unsigned long last_change = 0;
    
    if (millis() - last_change > 2000) {
        float variation = ((float)random(-50, 51)) / 100.0;
        current_temperature += variation;
        
        if (current_temperature < 15.0) current_temperature = 15.0;
        if (current_temperature > 35.0) current_temperature = 35.0;
        
        last_change = millis();
    }
    
    return current_temperature;
}

/* ================ I/O CALLBACKS =================================== */
static int EthernetSend(WOLFSSL* ssl, char* message, int sz, void* ctx) {
    (void)ssl; (void)ctx;
    if (!client.connected()) return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    
    size_t written = client.write((byte*)message, sz);
    
    // Contar bytes TX para métricas
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
    
    // Contar bytes RX para métricas
    if (currentTcpPhase != TCP_PHASE_NONE && ret > 0) {
        tcp_count_rx(ret);
    }
    
    return ret;
}

/* ================ SETUP FUNCTIONS ================================= */
int setup_network(void) {
    // CONFIGURACIÓN IDÉNTICA AL CÓDIGO QUE FUNCIONA
    WiFi.softAP(AP_SSID, AP_PASSWORD);
    
    delay(2000);  // Dar tiempo para establecer
    
    Serial.printf("AP \"%s\" listo. IP: %s, Puerto: %d\n",
                  AP_SSID, WiFi.softAPIP().toString().c_str(), TCP_PORT);
    
    return 0;
}

int setup_wolfssl(void) {
    MemorySnapshot before_wolfssl = take_memory_snapshot();
    enhanced_memory_tracking("Before_WolfSSL_Init");
    
    long t0 = micros();
    
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        Serial.println("Error: wolfSSL_Init falló");
        return -1;
    }
    
    //  TLS 1.3  
    WOLFSSL_METHOD* method = wolfTLSv1_3_server_method();
    if (method == NULL) {
        Serial.println("Error: método TLS 1.3 falló - intentando método flexible");
        method = wolfSSLv23_server_method();
        if (method == NULL) return -1;
    }
    
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) return -1;
    
    // Configuración específica de TLS 1.3
    if (wolfSSL_CTX_set_cipher_list(ctx, TLS13_CIPHER_LIST) != WOLFSSL_SUCCESS) {
        Serial.println("Advertencia: lista de cifrado TLS 1.3 falló, usando valores por defecto");
    }
    
 
    
    long t1 = micros();
    
    MemorySnapshot after_wolfssl = take_memory_snapshot();
    enhanced_memory_tracking("After_WolfSSL_Init");
    log_operation_memory_cost("WolfSSL_TLS13_Init", before_wolfssl, after_wolfssl);
    
    log_metric("TLS13_Context_Init", t1 - t0, "us");
    
    // ESTABLECER BASELINE DESPUÉS DE WOLFSSL
    set_memory_baseline();
    
    return 0;
}

int setup_certificates(void) {
    MemorySnapshot before_certs = take_memory_snapshot();
    enhanced_memory_tracking("Before_Cert_Load");
    
    long t0 = micros();
    
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
    
    wolfSSL_CTX_use_certificate_buffer(ctx, CTX_SERVER_CERT, CTX_SERVER_CERT_SIZE, CTX_CA_CERT_TYPE);
    wolfSSL_CTX_use_PrivateKey_buffer(ctx, CTX_SERVER_KEY, CTX_SERVER_KEY_SIZE, CTX_SERVER_KEY_TYPE);
    
    long t1 = micros();
    
    MemorySnapshot after_certs = take_memory_snapshot();
    enhanced_memory_tracking("After_Cert_Load");
    log_operation_memory_cost("TLS13_Certificates_Load", before_certs, after_certs);
    
    log_metric("TLS13_Certificates_Load", t1 - t0, "us");
    
    return 0;
}

/* ================ TLS HANDSHAKE HANDLER =========================== */
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
        Serial.printf("Handshake TLS 1.3 falló. Error: %d\n", error);
        wolfSSL_free(ssl);
        ssl = NULL;
        return;
    }
    
    long t1_handshake = micros();
    
    MemorySnapshot after_handshake = take_memory_snapshot();
    enhanced_memory_tracking("After_TLS13_Handshake");
    log_operation_memory_cost("TLS13_Handshake", before_handshake, after_handshake);
    
    t_handshake = millis();
    unsigned long t_tcp_handshake_out = millis();
    unsigned long tiempo_establecimiento = t_tcp_handshake_out - t_tcp_handshake_in;
    
    log_metric("TLS13_Handshake_Time", t1_handshake - t0_handshake, "us");
    log_metric("WiFi_TLS13_Handshake_Latency", tiempo_establecimiento, "ms");
    
    // Información del protocolo y cipher negociados
    const char* version = wolfSSL_get_version(ssl);
    const char* cipher = wolfSSL_get_cipher(ssl);
    Serial.printf("TLS conectado - Versión: %s, Cifrado: %s\n", version, cipher);
    
    // Verificar que se usó ECDH
    const char* curve_name = wolfSSL_get_curve_name(ssl);
    if (curve_name != NULL) {
        Serial.printf("Intercambio de claves ECDH: %s\n", curve_name);
        log_metric("ECDH_Curve_Used", 1, "boolean");
    } else {
        Serial.println("Advertencia: No se detectó intercambio ECDH");
        log_metric("ECDH_Curve_Used", 0, "boolean");
    }
    
    // Validación estricta de TLS 1.3
    if (wolfSSL_GetVersion(ssl) == WOLFSSL_TLSV1_3) {
        log_metric("TLS13_Negotiated", 1, "boolean");
        Serial.println(">> TLS 1.3 negociado exitosamente");
    } else {
        log_metric("TLS13_Negotiated", 0, "boolean");
        Serial.printf(">> Protocolo negociado: %s (no TLS 1.3)\n", version);
    }
    
    // Handshake completado - cambiar a fase DATA
    if (currentTcpPhase == TCP_PHASE_HANDSHAKE) {
        tcp_flush_phase_metrics("TCP_TLS13_Handshake_Complete");
        tcp_reset_phase(TCP_PHASE_DATA);
    }
    
    enhanced_memory_tracking("Handshake_Complete");
    tlsSessionActive = true;
    Serial.println(">> Sesión TLS 1.3 establecida correctamente.");
}

/* ================ TLS ENCRYPT AND SEND ============================ */
bool tlsEncryptAndSend(const char* message, bool detailed_metrics = false) {
    if (!ssl || !client.connected() || !tlsSessionActive) {
        return false;
    }
    
    MemorySnapshot before_encrypt, after_encrypt;
    if (detailed_metrics) {
        before_encrypt = take_memory_snapshot();
        enhanced_memory_tracking("Before_TLS13_Encrypt");
    }
    
    long t0_encrypt = micros();
    
    int bytes_sent = wolfSSL_write(ssl, message, strlen(message));
    
    long t1_encrypt = micros();
    
    if (detailed_metrics) {
        after_encrypt = take_memory_snapshot();
        enhanced_memory_tracking("After_TLS13_Encrypt");
        log_operation_memory_cost("TLS13_Encrypt_Send", before_encrypt, after_encrypt);
    }
    
    if (bytes_sent > 0) {
        log_metric("TLS13_Encrypt_Send", t1_encrypt - t0_encrypt, "us");
        return true;
    } else {
        Serial.println("Error en wolfSSL_write");
        return false;
    }
}

/* ================ ARDUINO SETUP =================================== */
void setup(void) {
    Serial.begin(115200);
    delay(1000);
    
    Serial.println("Servidor de Temperatura ESP32 TLS 1.3");
    Serial.printf("Memoria libre: %d bytes\n", ESP.getFreeHeap());
    
    randomSeed(analogRead(0));
    
    // INICIALIZAR BASELINE DE MEMORIA
    init_memory_baseline();
    
    // Métricas Flash/RAM iniciales
    log_flash_app_size();
    log_static_ram();
    enhanced_memory_tracking("Initial_Setup");
    
    if (setup_network() != 0) {
        Serial.println("Error: configuración de red falló");
        while(1) delay(1000);
    }
    
    if (setup_wolfssl() != 0) {
        Serial.println("Error: configuración wolfSSL TLS 1.3 falló");
        while(1) delay(1000);
    }
    
    if (setup_certificates() != 0) {
        Serial.println("Error: configuración de certificados falló");
        while(1) delay(1000);
    }
    
    wolfSSL_SetIOSend(ctx, EthernetSend);
    wolfSSL_SetIORecv(ctx, EthernetReceive);
    
    server.begin();
    
    Serial.printf("Servidor TLS 1.3 listo en %s:%d\n", WiFi.softAPIP().toString().c_str(), TCP_PORT);
    Serial.printf("Memoria libre después de configuración: %d bytes\n", ESP.getFreeHeap());
    
    enhanced_memory_tracking("Complete_Setup");
}

/* ================ MAIN LOOP ======================================= */
void loop() {
     
    if (!client || !client.connected()) {
        if (client) {
            Serial.println("<< Cliente anterior desconectado.");
            client.stop();
            tlsSessionActive = false;
            if (ssl) {
                wolfSSL_shutdown(ssl);
                wolfSSL_free(ssl);
                ssl = NULL;
            }
            log_metric("Session_Ended_By_Disconnect", millis(), "ms");

            // Métricas finales de sesión
            log_session_memory_summary();

            if (currentTcpPhase == TCP_PHASE_DATA) {
                tcp_flush_phase_metrics("TCP_TLS13_Data_Total_OnDisconnect");
            } else if (currentTcpPhase == TCP_PHASE_HANDSHAKE) {
                tcp_flush_phase_metrics("TCP_TLS13_Handshake_Incomplete_OnDisconnect");
            }
            tcp_reset_phase(TCP_PHASE_NONE);
        }

        client = server.available();
        if (!client) {
            delay(100);
            return;
        }

        t_tcp_handshake_in = millis();
        Serial.printf(">> Nuevo cliente conectado: %s (handshake TLS 1.3 empezará ahora)\n",
                      client.remoteIP().toString().c_str());

        tcp_reset_phase(TCP_PHASE_HANDSHAKE);
        
        // Resetear métricas de sesión
        heap_min = SIZE_MAX;
        heap_max_used = 0;
        enhanced_memory_tracking("Connection_Start");
        
        handle_tls_handshake();
        return;
    }

    // Leer datos TLS si hay disponibles
    if (tlsSessionActive && ssl && client.available() > 0) {
        char recv_buffer[128];
        int received = wolfSSL_read(ssl, recv_buffer, sizeof(recv_buffer) - 1);
        if (received > 0) {
            recv_buffer[received] = '\0';
            
            if (strncmp(recv_buffer, "TEMP_RPI:", 9) == 0) {
                float client_temp = atof(recv_buffer + 9);
                Serial.printf("<< %.2f°C\n", client_temp);
                
                const char* ack = "ACK_TEMP";
                wolfSSL_write(ssl, ack, strlen(ack));
            }
        } else if (received < 0) {
            int error = wolfSSL_get_error(ssl, received);
            if (error != WOLFSSL_ERROR_WANT_READ && error != WOLFSSL_ERROR_WANT_WRITE) {
                Serial.printf("Error leyendo datos TLS 1.3. Error: %d\n", error);
                client.stop();
                return;
            }
        }
    }

    // Envío de temperatura cifrada: exactamente 25 notificaciones, cada 1000ms
    static int temp_notif_count = 0;
    if (tlsSessionActive && temp_notif_count < 25 && (millis() - t_lastTemp >= TEMP_INTERVAL_MS)) {
        t_lastTemp = millis();
        current_temperature += 0.5;
        if (current_temperature > 35.0) current_temperature = 20.0;

        char temp_text[64];
        snprintf(temp_text, sizeof(temp_text), "TEMP_ESP32:%.2f", current_temperature);

        // Solo métricas detalladas en las primeras 2 temperaturas
        bool show_detailed_metrics = (temp_notif_count < 2);
        
        if (tlsEncryptAndSend(temp_text, show_detailed_metrics)) {
            temp_notif_count++;
            log_metric("Temp_Notifs_Sent_TLS13", temp_notif_count, "count");
            
            // Imprimir TODAS las temperaturas enviadas
            Serial.printf(">> %.2f°C (msg %d/25) - TLS 1.3\n", current_temperature, temp_notif_count);
        } else {
            Serial.println("!! Fallo al enviar temperatura cifrada TLS 1.3.");
        }

        // Si alcanzamos 25 notificaciones, volcamos métricas finales
        if (temp_notif_count == 25) {
            tcp_flush_phase_metrics("TCP_TLS13_Data_Total");
            enhanced_memory_tracking("After_25_Notifications");
        }
    }

    // Status cada 30 segundos
    static unsigned long last_status = 0;
    if (millis() - last_status > 30000) {
        last_status = millis();
        Serial.printf("Clientes: %d, Memoria: %d, Memoria Min: %d\n", 
                      WiFi.softAPgetStationNum(), ESP.getFreeHeap(), heap_min);
        log_metric("Periodic_Heap_Check", esp_get_free_heap_size(), "bytes");
        log_metric("Periodic_Heap_Min", heap_min, "bytes");
    }
    
    // Ceder control si no hay nada más que procesar
    if (!client.available()) {
        delay(10);
    }
}
