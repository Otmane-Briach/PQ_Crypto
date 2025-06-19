
/*
 * 
 * --------------------------------------------------------------------
 * Cliente TLS 1.3 RPi que SOLO RECIBE temperaturas 
 * Recibe 25 temperaturas, métricas completas TLS 1.3
 * g++ -o cliente_tls_completo cliente_tls_completo.cpp -lwolfssl -pthread -DWOLFSSL_TLS13
 * ------------------------------------------------------------------
 */

// IMPORTANTE: wolfssl/options.h DEBE IR PRIMERO 
#define WOLFSSL_USE_OPTIONS_H
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <iostream>
#include <chrono>
#include <thread>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <iomanip>
/* ---------- CONFIGURACIÓN IDÉNTICA AL SERVIDOR ESP32 TLS 1.3 ------ */
const char* ESP32_IP = "192.168.4.1";
const int ESP32_PORT = 12345;

/* TLS 1.3 Cipher list que coincide con el servidor */
#define TLS13_CIPHER_LIST "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"

/* ---------- Variables globales ------------------------------------- */
WOLFSSL_CTX* ctx = nullptr;
WOLFSSL* ssl = nullptr;
int sockfd = -1;

// Variables para métricas
static std::chrono::high_resolution_clock::time_point connection_start;
static std::chrono::high_resolution_clock::time_point handshake_start;
static std::chrono::high_resolution_clock::time_point handshake_end;
static std::chrono::high_resolution_clock::time_point data_phase_start;
static int temp_received_count = 0;

/* ---------- MÉTRICAS TLS 1.3 ------------------------------------ */
void log_metric(const char* name, unsigned long value, const char* unit) {
    std::cout << "[METRIC_WIFI_TLS13_CLIENT], " << name << ", " << value << ", " << unit << std::endl;
}

 
bool connectToESP32() {
    connection_start = std::chrono::high_resolution_clock::now();

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        std::cerr << "Error creando socket" << std::endl;
        return false;
    }

    // Configurar timeout para el socket
    struct timeval timeout;
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(ESP32_PORT);

    if (inet_pton(AF_INET, ESP32_IP, &server_addr.sin_addr) <= 0) {
        std::cerr << "Dirección IP inválida: " << ESP32_IP << std::endl;
        close(sockfd);
        return false;
    }

    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Error conectando a " << ESP32_IP << ":" << ESP32_PORT << std::endl;
        close(sockfd);
        return false;
    }

    auto connection_end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(connection_end - connection_start);
    log_metric("TCP_Connection_Time", duration.count(), "us");

    std::cout << ">> Conectado a ESP32 en " << ESP32_IP << ":" << ESP32_PORT << std::endl;
    return true;
}

void disconnectFromESP32() {
    if (sockfd >= 0) {
        close(sockfd);
        sockfd = -1;
        std::cout << "<< Desconectado del ESP32" << std::endl;
    }
}

/* ---------- wolfSSL TLS 1.3 setup --------------------------------- */
bool setup_wolfssl_tls13() {
    auto start = std::chrono::high_resolution_clock::now();

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        std::cerr << "wolfSSL_Init falló" << std::endl;
        return false;
    }

    // TLS 1.3 CLIENT METHOD  
    WOLFSSL_METHOD* method = NULL;

    // Intentar TLS 1.3 específico primero
    #ifdef WOLFSSL_TLS13
    method = wolfTLSv1_3_client_method();
    if (method == nullptr) {
        std::cerr << "TLS 1.3 specific method failed, trying flexible method" << std::endl;
    }
    #endif

    // Fallback a método flexible que soporta TLS 1.3
    if (method == nullptr) {
        method = wolfSSLv23_client_method();
        if (method == nullptr) return false;
    }

    ctx = wolfSSL_CTX_new(method);
    if (ctx == nullptr) return false;

 
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);

    //  FORZAR TLS 1.3 ESPECÍFICAMENTE  
    #ifdef WOLFSSL_TLS13
    // Establecer versión mínima y máxima a TLS 1.3 si las funciones están disponibles
    #ifdef HAVE_WOLFSSL_SET_MIN_MAX_VERSION
    if (wolfSSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != WOLFSSL_SUCCESS) {
        std::cerr << "Warning: No se pudo establecer TLS 1.3 como versión mínima" << std::endl;
    }
    if (wolfSSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != WOLFSSL_SUCCESS) {
        std::cerr << "Warning: No se pudo establecer TLS 1.3 como versión máxima" << std::endl;
    }
    #else
    // Método alternativo para forzar TLS 1.3
    wolfSSL_CTX_set_options(ctx, WOLFSSL_OP_NO_SSLv2 | WOLFSSL_OP_NO_SSLv3 | WOLFSSL_OP_NO_TLSv1 | WOLFSSL_OP_NO_TLSv1_1 | WOLFSSL_OP_NO_TLSv1_2);
    #endif
    #endif

    //   CONFIGURACIÓN TLS 1.3 ESPECÍFICA  
    if (wolfSSL_CTX_set_cipher_list(ctx, TLS13_CIPHER_LIST) != WOLFSSL_SUCCESS) {
        std::cerr << "Warning: TLS 1.3 cipher list failed, using defaults" << std::endl;
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    log_metric("TLS13_Context_Init_Client", duration.count(), "us");

    std::cout << "wolfSSL TLS 1.3 configurado" << std::endl;
    return true;
}

/* ---------- Recepción de temperaturas TLS 1.3 -------------------- */
bool receive_temperatures_tls13() {
    ssl = wolfSSL_new(ctx);
    if (ssl == nullptr) {
        std::cerr << "Error: wolfSSL_new falló" << std::endl;
        return false;
    }

    if (wolfSSL_set_fd(ssl, sockfd) != WOLFSSL_SUCCESS) {
        std::cerr << "Error: wolfSSL_set_fd falló" << std::endl;
        wolfSSL_free(ssl);
        return false;
    }

    // Handshake TLS 1.3
    std::cout << "Iniciando handshake TLS 1.3..." << std::endl;
    handshake_start = std::chrono::high_resolution_clock::now();

    if (wolfSSL_connect(ssl) != WOLFSSL_SUCCESS) {
        int error = wolfSSL_get_error(ssl, 0);
        std::cerr << "TLS 1.3 handshake falló. Error: " << error << std::endl;
        wolfSSL_free(ssl);
        return false;
    }

    handshake_end = std::chrono::high_resolution_clock::now();

    auto handshake_duration = std::chrono::duration_cast<std::chrono::microseconds>(handshake_end - handshake_start);
    auto total_connection_time = std::chrono::duration_cast<std::chrono::milliseconds>(handshake_end - connection_start);

    log_metric("TLS13_Handshake_Time_Client", handshake_duration.count(), "us");
    log_metric("WiFi_TLS13_Connection_Latency_Client", total_connection_time.count(), "ms");

    // Información del protocolo y cipher negociados
    const char* version = wolfSSL_get_version(ssl);
    const char* cipher = wolfSSL_get_cipher(ssl);
    std::cout << "TLS conectado - Version: " << version << ", Cipher: " << cipher << std::endl;

    // Verificar que se usó ECDH
    const char* curve_name = wolfSSL_get_curve_name(ssl);
    if (curve_name != NULL) {
        std::cout << "ECDH Key Exchange: " << curve_name << std::endl;
        log_metric("ECDH_Curve_Used", 1, "boolean");
    } else {
        std::cout << "Warning: No se detectó intercambio ECDH" << std::endl;
        log_metric("ECDH_Curve_Used", 0, "boolean");
    }

    // Verificar que efectivamente estamos usando TLS 1.3
    if (wolfSSL_GetVersion(ssl) == WOLFSSL_TLSV1_3) {
        log_metric("TLS13_Negotiated_Client", 1, "boolean");
        std::cout << ">> TLS 1.3 negociado exitosamente en cliente" << std::endl;
    } else {
        log_metric("TLS13_Negotiated_Client", 0, "boolean");
        std::cout << ">> Warning: No se negoció TLS 1.3" << std::endl;
    }

    // Inicio de fase de datos
    data_phase_start = std::chrono::high_resolution_clock::now();
    temp_received_count = 0;

    std::cout << "\n>> Esperando temperaturas cifradas TLS 1.3 del ESP32...\n" << std::endl;

    char recv_buffer[128];
    bool connection_active = true;

    while (connection_active && temp_received_count < 25) {
        // Marca el inicio de la operación de descifrado
        auto decrypt_start = std::chrono::high_resolution_clock::now();
        
        // Lee datos cifrados desde la conexión TLS 1.3
        int ret = wolfSSL_read(ssl, recv_buffer, sizeof(recv_buffer) - 1);
        
        // Marca el fin de la operación de descifrado
        auto decrypt_end = std::chrono::high_resolution_clock::now();

        if (ret > 0) {
            // Calcula y registra el tiempo que tardó el descifrado
            auto decrypt_duration = std::chrono::duration_cast<std::chrono::microseconds>(decrypt_end - decrypt_start);
            log_metric("TLS13_Decrypt_Receive_Client", decrypt_duration.count(), "us");

            // Añade terminador de cadena para poder tratar recv_buffer como texto
            recv_buffer[ret] = '\0';

            // Si el mensaje empieza con "TEMP_ESP32:", extrae la temperatura
            if (strncmp(recv_buffer, "TEMP_ESP32:", 11) == 0) {
                float esp32_temp = atof(recv_buffer + 11);
                temp_received_count++;
                
                // Muestra por consola el tamaño de datos recibidos y la temperatura
                std::cout << "Datos recibidos: " << ret << " bytes (TLS 1.3 AEAD)" << std::endl;
                std::cout << "Temperatura descifrada: " 
                        << std::fixed << std::setprecision(2) 
                        << esp32_temp << "°C" << std::endl;
                
                // Cuenta cuántas temperaturas han llegado por TLS
                log_metric("Temp_Received_Count_TLS13", temp_received_count, "count");

                // Si ya recibimos las 25 temperaturas, calculamos latencia total y salimos
                if (temp_received_count == 25) {
                    auto data_phase_end = std::chrono::high_resolution_clock::now();
                    auto total_data_time = std::chrono::duration_cast<std::chrono::milliseconds>(data_phase_end - data_phase_start);
                    log_metric("Total_Data_Phase_Time_TLS13", total_data_time.count(), "ms");
                    log_metric("Temperature_Reception_Complete_TLS13", 25, "count");
                    std::cout << "\n>> ¡Recibidas todas las 25 temperaturas vía TLS 1.3!" << std::endl;
                    break;
                }
            } else {
                // Para otros tipos de mensajes (ACKs, estado, etc.), solo lo mostramos
                std::cout << "Mensaje TLS 1.3 recibido: " << recv_buffer << std::endl;
            }
        }
        else if (ret < 0) {
            // Si ocurre un error distinto a WANT_READ/WRITE, lo reportamos y cerramos
            int error = wolfSSL_get_error(ssl, ret);
            if (error != WOLFSSL_ERROR_WANT_READ && error != WOLFSSL_ERROR_WANT_WRITE) {
                std::cerr << "Error leyendo datos TLS 1.3. Error: " << error << std::endl;
                connection_active = false;
            }
        }
        else if (ret == 0) {
            // El servidor cerró la conexión TLS
            std::cout << "Conexión TLS 1.3 cerrada por el servidor" << std::endl;
            connection_active = false;
        }

        // Pequeña pausa para no saturar la CPU
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }


    auto cleanup_start = std::chrono::high_resolution_clock::now();
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    auto cleanup_end = std::chrono::high_resolution_clock::now();

    auto cleanup_duration = std::chrono::duration_cast<std::chrono::microseconds>(cleanup_end - cleanup_start);
    log_metric("TLS13_Cleanup_Time_Client", cleanup_duration.count(), "us");

    return temp_received_count == 25;
}

/* ---------- Main --------------------------------------------------- */
// Función principal: inicializa TLS, realiza conexión y recepción de temperaturas
int main() {
    // Mensaje inicial indicando función del cliente
    std::cout << "Cliente TLS 1.3 Temperature RPi - Solo Receptor (Compatible ESP32 TLS 1.3)" << std::endl;

    // Marca el inicio del programa para medir tiempo total
    auto program_start = std::chrono::high_resolution_clock::now();

    // Configuración de wolfSSL para TLS 1.3
    if (!setup_wolfssl_tls13()) {
        std::cerr << "Error en setup wolfSSL TLS 1.3" << std::endl;
        return -1;
    }

    // Variables de control de intentos y estado de éxito
    int attempts = 0;
    const int max_attempts = 5;
    bool success = false;

    // Bucle de reintentos hasta max_attempts o hasta éxito
    while (attempts < max_attempts && !success) {
        std::cout << "Intento " << (attempts + 1) << "/" << max_attempts << " (TLS 1.3)" << std::endl;

        // Intento de conexión y recepción de datos TLS
        if (connectToESP32()) {
            if (receive_temperatures_tls13()) {
                std::cout << " Recepción de temperaturas TLS 1.3 exitosa" << std::endl;
                success = true;
            } else {
                std::cerr << "Error en recepción de temperaturas TLS 1.3" << std::endl;
            }
            // Desconexión tras intento
            disconnectFromESP32();
        } else {
            std::cerr << "Error conectando al ESP32" << std::endl;
        }

        attempts++;
        // Espera antes de reintentar conexión
        if (attempts < max_attempts && !success) {
            std::cout << "Reintentando en 10s..." << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(10));
        }
    }

    // Mide y registra tiempo total de ejecución del programa
    auto program_end = std::chrono::high_resolution_clock::now();
    auto total_program_time = std::chrono::duration_cast<std::chrono::milliseconds>(program_end - program_start);
    log_metric("Total_Program_Runtime_TLS13", total_program_time.count(), "ms");

    // Limpieza y liberación de contexto wolfSSL, midiendo duración
    if (ctx) {
        auto ctx_cleanup_start = std::chrono::high_resolution_clock::now();
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
        auto ctx_cleanup_end = std::chrono::high_resolution_clock::now();
        auto ctx_cleanup_duration = std::chrono::duration_cast<std::chrono::microseconds>(ctx_cleanup_end - ctx_cleanup_start);
        log_metric("TLS13_Context_Cleanup_Client", ctx_cleanup_duration.count(), "us");
    }

    // Mensaje de finalización del cliente
    std::cout << ">> Cliente TLS 1.3 finalizado." << std::endl;

    // Registra el resultado de la sesión: éxito o fallo
    if (success) {
        log_metric("Session_Result_TLS13", 1, "success");
        std::cout << "Resultado: ÉXITO - 25 temperaturas TLS 1.3 recibidas correctamente" << std::endl;
    } else {
        log_metric("Session_Result_TLS13", 0, "failure");
        std::cout << "Resultado: FALLO - No se pudieron recibir todas las temperaturas TLS 1.3" << std::endl;
    }

    return success ? 0 : -1;
}
