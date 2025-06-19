/*
 * rpi_tls13_pqc_hybrid_client.cpp
 * --------------------------------------------------------------------
  
g++ -o rpi_tls13_pqc_hybrid_client rpi_tls13_pqc_hybrid_client.cpp     -lwolfssl -std=c++17 -pthread

 * ------------------------------------------------------------------
 */

// *** IMPORTANTE: wolfssl/options.h DEBE IR PRIMERO ***
#define WOLFSSL_USE_OPTIONS_H
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <iostream>
#include <chrono>
#include <thread>
#include <cstring>
#include <fstream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <vector>
#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <algorithm>

// wolfSSL para criptografía (evita conflictos con OpenSSL)
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>

// Constantes para compatibilidad
#ifndef WC_SHA256_DIGEST_SIZE
#define WC_SHA256_DIGEST_SIZE 32
#endif

/* ---------- CONFIGURACIÓN IDÉNTICA AL SERVIDOR HÍBRIDO ----------- */
const char* ESP32_IP = "192.168.4.1";
const int ESP32_PORT = 12345;

/* TLS 1.3 Cipher list que coincide con el servidor */
#define TLS13_CIPHER_LIST "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"

/* ---------- Constantes PQC  --------- */
// MsgTypes PQC
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

// Longitudes fijas PQC
const int CLI_CERT_LEN   = 3746;
const int SRV_CERT_LEN   = 3746;
const int DIL_PUB        = 1312;
const int DIL_SIG        = 2420;
const int KYB_PUB        = 800;
const int KYB_CT         = 768;
const int SEC_MSG        = 64;
const int CERT_BODY_SIZE = 2 + 4 + 4 + 4 + DIL_PUB;  // 1326 bytes

/* ---------- Rutas de archivos PQC --------------------------------- */
const char* CERT_DIR = "./certs";
const char* CA_PUB_FILE = "./certs/ca_pub.bin";
const char* CLI_CERT_FILE = "./certs/cli_cert.bin";

// Binarios de verificación PQC (IDÉNTICOS AL CLIENTE PYTHON)
const char* VERIFY_CERT_BIN = "./verify_server_cert";
const char* VERIFY_SIG_BIN = "./verify_dilithium_sig";
const char* KEM_ENCAP_BIN = "./kyber_encapsulate";

/* ---------- Variables globales ------------------------------------- */
WOLFSSL_CTX* ctx = nullptr;
WOLFSSL* ssl = nullptr;
int sockfd = -1;

// Variables para métricas
static std::chrono::high_resolution_clock::time_point connection_start;
static std::chrono::high_resolution_clock::time_point tls_handshake_start;
static std::chrono::high_resolution_clock::time_point tls_handshake_end;
static std::chrono::high_resolution_clock::time_point pqc_handshake_start;
static std::chrono::high_resolution_clock::time_point pqc_handshake_end;
static std::chrono::high_resolution_clock::time_point data_phase_start;
static int temp_received_count = 0;

// Estados de sesión
static bool tlsSessionActive = false;
static bool pqcSessionActive = false;

/* ---------- MÉTRICAS TLS 1.3 + PQC ------------------------------- */
void log_metric(const char* name, unsigned long value, const char* unit) {
    std::cout << "[METRIC_WIFI_TLS13_PQC_HYBRID_CLIENT], " << name << ", " << value << ", " << unit << std::endl;
}

/* ---------- FUNCIONES CRIPTOGRÁFICAS PQC -------------------------- */

// Verificar HMAC-SHA256 usando directamente shared secret de Kyber (igual que servidor ESP32)
bool verify_hmac_with_kyber_key(const std::vector<uint8_t>& data, const std::vector<uint8_t>& received_mac, 
                                const std::vector<uint8_t>& kyber_shared_secret) {
    Hmac hmac_ctx;
    unsigned char computed_mac[WC_SHA256_DIGEST_SIZE];
    
    int ret = wc_HmacInit(&hmac_ctx, NULL, -1);
    if (ret != 0) return false;
    
    // Usar directamente el shared secret de Kyber (KYBER_SS_BYTES = 32)
    ret = wc_HmacSetKey(&hmac_ctx, WC_SHA256, kyber_shared_secret.data(), 32);
    if (ret != 0) {
        wc_HmacFree(&hmac_ctx);
        return false;
    }
    
    ret = wc_HmacUpdate(&hmac_ctx, data.data(), data.size());
    if (ret != 0) {
        wc_HmacFree(&hmac_ctx);
        return false;
    }
    
    ret = wc_HmacFinal(&hmac_ctx, computed_mac);
    wc_HmacFree(&hmac_ctx);
    if (ret != 0) return false;
    
    if (received_mac.size() != WC_SHA256_DIGEST_SIZE) {
        return false;
    }
    
    return memcmp(computed_mac, received_mac.data(), WC_SHA256_DIGEST_SIZE) == 0;
}

// Descifrar AES-CBC usando directamente shared secret de Kyber (igual que servidor ESP32)
std::string aes_decrypt_cbc_with_kyber_key(const std::vector<uint8_t>& ciphertext, 
                                           const std::vector<uint8_t>& kyber_shared_secret, 
                                           const std::vector<uint8_t>& iv) {
    Aes aes;
    int ret = wc_AesInit(&aes, NULL, -1);
    if (ret != 0) {
        throw std::runtime_error("Error inicializando AES");
    }
    
    // Configurar clave usando directamente shared secret de Kyber (32 bytes = AES-256)
    ret = wc_AesSetKey(&aes, kyber_shared_secret.data(), 32, iv.data(), AES_DECRYPTION);
    if (ret != 0) {
        wc_AesFree(&aes);
        throw std::runtime_error("Error configurando clave AES con shared secret Kyber");
    }
    
    // Buffer para texto descifrado
    std::vector<uint8_t> plaintext(ciphertext.size());
    
    // Descifrar
    ret = wc_AesCbcDecrypt(&aes, plaintext.data(), ciphertext.data(), ciphertext.size());
    wc_AesFree(&aes);
    if (ret != 0) {
        throw std::runtime_error("Error en descifrado AES");
    }
    
    // Remover padding PKCS7 manualmente (igual que servidor ESP32)
    if (plaintext.empty()) {
        throw std::runtime_error("Texto descifrado vacío");
    }
    
    uint8_t pad_val = plaintext.back();
    if (pad_val == 0 || pad_val > 16) {
        throw std::runtime_error("Padding PKCS7 inválido");
    }
    
    // Verificar que todos los bytes de padding sean correctos
    for (int i = 1; i <= pad_val; i++) {
        if (plaintext[plaintext.size() - i] != pad_val) {
            throw std::runtime_error("Padding PKCS7 inconsistente");
        }
    }
    
    // Remover padding y convertir a string
    size_t actual_len = plaintext.size() - pad_val;
    return std::string(plaintext.begin(), plaintext.begin() + actual_len);
}

/* ---------- UTILIDADES AUXILIARES --------------------------------- */
std::string bytesToHex(const std::vector<uint8_t>& bytes, int limit = 16) {
    std::ostringstream oss;
    for (int i = 0; i < std::min((int)bytes.size(), limit); ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << std::uppercase << (int)bytes[i];
    }
    if (bytes.size() > limit) oss << "...";
    return oss.str();
}

std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::vector<uint8_t> readFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("No se pudo abrir el archivo: " + filename);
    }
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)), 
                                std::istreambuf_iterator<char>());
}

void writeFile(const std::string& filename, const std::vector<uint8_t>& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("No se pudo escribir el archivo: " + filename);
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

std::string runCommand(const std::string& command) {
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        throw std::runtime_error("Error ejecutando comando: " + command);
    }
    
    char buffer[128];
    std::string result = "";
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    
    int status = pclose(pipe);
    if (status != 0) {
        throw std::runtime_error("Comando falló: " + command + " (código: " + std::to_string(status) + ")");
    }
    
    return result;
}

/* ---------- CONEXIÓN TCP  --- */
bool connectToESP32() {
    connection_start = std::chrono::high_resolution_clock::now();

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        std::cerr << "Error creando socket" << std::endl;
        return false;
    }

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

/* ---------- wolfSSL TLS 1.3 setup  */
bool setup_wolfssl_tls13() {
    auto start = std::chrono::high_resolution_clock::now();

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        std::cerr << "wolfSSL_Init falló" << std::endl;
        return false;
    }

    //  TLS 1.3 CLIENT METHOD  
    WOLFSSL_METHOD* method = NULL;

    #ifdef WOLFSSL_TLS13
    method = wolfTLSv1_3_client_method();
    if (method == nullptr) {
        std::cerr << "TLS 1.3 specific method failed, trying flexible method" << std::endl;
    }
    #endif

    if (method == nullptr) {
        method = wolfSSLv23_client_method();
        if (method == nullptr) return false;
    }

    ctx = wolfSSL_CTX_new(method);
    if (ctx == nullptr) return false;

    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);

    #ifdef WOLFSSL_TLS13
    #ifdef HAVE_WOLFSSL_SET_MIN_MAX_VERSION
    if (wolfSSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != WOLFSSL_SUCCESS) {
        std::cerr << "Warning: No se pudo establecer TLS 1.3 como versión mínima" << std::endl;
    }
    if (wolfSSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != WOLFSSL_SUCCESS) {
        std::cerr << "Warning: No se pudo establecer TLS 1.3 como versión máxima" << std::endl;
    }
    #else
    wolfSSL_CTX_set_options(ctx, WOLFSSL_OP_NO_SSLv2 | WOLFSSL_OP_NO_SSLv3 | WOLFSSL_OP_NO_TLSv1 | WOLFSSL_OP_NO_TLSv1_1 | WOLFSSL_OP_NO_TLSv1_2);
    #endif
    #endif

    if (wolfSSL_CTX_set_cipher_list(ctx, TLS13_CIPHER_LIST) != WOLFSSL_SUCCESS) {
        std::cerr << "Warning: TLS 1.3 cipher list failed, using defaults" << std::endl;
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    log_metric("TLS13_Context_Init_Client", duration.count(), "us");

    std::cout << "wolfSSL TLS 1.3 configurado" << std::endl;
    return true;
}

/* ---------- PQC FRAMING OVER TLS ---------------------------------- */
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

bool sendPQCFrame(PQCMsgType t, const std::vector<uint8_t>& payload = std::vector<uint8_t>()) {
    if (!ssl || !tlsSessionActive) return false;
    
    std::cout << "\n>> Enviando frame PQC sobre TLS: " << pqcMsgTypeName(t) 
              << " (payload " << payload.size() << " bytes)" << std::endl;
    
    // Header: 1 byte tipo + 2 bytes longitud
    uint8_t header[3];
    header[0] = static_cast<uint8_t>(t);
    header[1] = static_cast<uint8_t>(payload.size() >> 8);
    header[2] = static_cast<uint8_t>(payload.size() & 0xFF);
    
    // Enviar header por TLS
    if (wolfSSL_write(ssl, header, 3) != 3) {
        std::cerr << "!! Error enviando header PQC por TLS" << std::endl;
        return false;
    }
    
    // Enviar payload si existe
    if (!payload.empty()) {
        if (wolfSSL_write(ssl, payload.data(), payload.size()) != static_cast<int>(payload.size())) {
            std::cerr << "!! Error enviando payload PQC por TLS" << std::endl;
            return false;
        }
    }
    
    return true;
}

std::pair<PQCMsgType, std::vector<uint8_t>> recvPQCFrame(uint32_t timeout_ms = 10000) {
    if (!ssl || !tlsSessionActive) {
        throw std::runtime_error("TLS no activo para recibir frame PQC");
    }
    
    // Leer header (3 bytes)
    uint8_t header[3];
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < 3; ++i) {
        int ret = wolfSSL_read(ssl, &header[i], 1);
        if (ret != 1) {
            auto current_time = std::chrono::high_resolution_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(current_time - start_time);
            if (elapsed.count() > timeout_ms) {
                throw std::runtime_error("Timeout leyendo header PQC");
            }
            int error = wolfSSL_get_error(ssl, ret);
            if (error != WOLFSSL_ERROR_WANT_READ && error != WOLFSSL_ERROR_WANT_WRITE) {
                throw std::runtime_error("Error leyendo header PQC: " + std::to_string(error));
            }
            --i; // Reintentar este byte
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    
    PQCMsgType msg_type = static_cast<PQCMsgType>(header[0]);
    uint16_t payload_len = (static_cast<uint16_t>(header[1]) << 8) | header[2];
    
    std::cout << "<< Datos recibidos con PQC sobre TLS:" << payload_len << " bytes" << std::endl;
    // Leer payload si existe
    std::vector<uint8_t> payload;
    if (payload_len > 0) {
        payload.resize(payload_len);
        int total_read = 0;
        while (total_read < payload_len) {
            int ret = wolfSSL_read(ssl, payload.data() + total_read, payload_len - total_read);
            if (ret > 0) {
                total_read += ret;
            } else {
                auto current_time = std::chrono::high_resolution_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(current_time - start_time);
                if (elapsed.count() > timeout_ms) {
                    throw std::runtime_error("Timeout leyendo payload PQC");
                }
                int error = wolfSSL_get_error(ssl, ret);
                if (error != WOLFSSL_ERROR_WANT_READ && error != WOLFSSL_ERROR_WANT_WRITE) {
                    throw std::runtime_error("Error leyendo payload PQC: " + std::to_string(error));
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }
    }
    
    return std::make_pair(msg_type, payload);
}

/* ---------- VERIFICACIONES PQC (IDÉNTICAS AL CLIENTE PYTHON) ------ */
bool verify_cert(const std::vector<uint8_t>& cert) {
    std::cout << "\nCertificado del servidor recibido." << std::endl;
    std::cout << "  Inicio: " << bytesToHex(cert, 16) << std::endl;
    std::cout << "  Final : " << bytesToHex(std::vector<uint8_t>(cert.end()-16, cert.end()), 16) << std::endl;
    
    // Escribir certificado a archivo temporal
    std::string temp_cert = "/tmp/temp_srv_cert.bin";
    writeFile(temp_cert, cert);
    
    try {
        std::string command = std::string(VERIFY_CERT_BIN) + " " + temp_cert + " " + CA_PUB_FILE;
        std::string result = runCommand(command);
        
        std::cout << "\nValidación de fechas y firma:" << std::endl;
        std::cout << result << std::endl;
        
        unlink(temp_cert.c_str());
        return true;
    } catch (const std::exception& e) {
        unlink(temp_cert.c_str());
        std::cerr << "Error verificando certificado: " << e.what() << std::endl;
        return false;
    }
}

bool verify_sig(const std::vector<uint8_t>& srv_pub, const std::vector<uint8_t>& msg, const std::vector<uint8_t>& sig) {
    std::string temp_pub = "/tmp/temp_srv_pub.bin";
    std::string temp_msg = "/tmp/temp_msg.bin";
    std::string temp_sig = "/tmp/temp_sig.bin";
    
    try {
        writeFile(temp_pub, srv_pub);
        writeFile(temp_msg, msg);
        writeFile(temp_sig, sig);
        
        std::string command = std::string(VERIFY_SIG_BIN) + " " + temp_pub + " " + 
                             temp_msg + " " + temp_sig + " " + CA_PUB_FILE;
        runCommand(command);
        
        unlink(temp_pub.c_str());
        unlink(temp_msg.c_str());
        unlink(temp_sig.c_str());
        return true;
    } catch (const std::exception& e) {
        unlink(temp_pub.c_str());
        unlink(temp_msg.c_str());
        unlink(temp_sig.c_str());
        std::cerr << "Error verificando firma: " << e.what() << std::endl;
        return false;
    }
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encapsulate(const std::vector<uint8_t>& kyb_pub) {
    std::cout << "\nClave pública Kyber recibida:" << std::endl;
    std::cout << "  Inicio: " << bytesToHex(kyb_pub, 16) << " bytes totales: " << kyb_pub.size() << std::endl;
    
    std::string temp_pub = "/tmp/temp_kyb_pub.bin";
    std::string temp_ct = "/tmp/temp_kyb_ct.bin";
    
    try {
        writeFile(temp_pub, kyb_pub);
        
        std::string command = std::string(KEM_ENCAP_BIN) + " " + temp_pub + " " + temp_ct;
        std::string result = runCommand(command);
        
        // El shared secret viene en stdout como hex
        std::string ss_hex = result;
        // Remover caracteres de nueva línea y espacios de forma simple
        std::string cleaned_hex;
        for (char c : ss_hex) {
            if (c != '\n' && c != '\r' && c != ' ' && c != '\t') {
                cleaned_hex += c;
            }
        }
        ss_hex = cleaned_hex;
        
        std::vector<uint8_t> shared_secret = hexToBytes(ss_hex);
        std::vector<uint8_t> ciphertext = readFile(temp_ct);
        
        std::cout << "\nEncapsulación completa." << std::endl;
        std::cout << "  Shared secret: " << bytesToHex(shared_secret, 32) << std::endl;
        
        unlink(temp_pub.c_str());
        unlink(temp_ct.c_str());
        
        return std::make_pair(shared_secret, ciphertext);
    } catch (const std::exception& e) {
        unlink(temp_pub.c_str());
        unlink(temp_ct.c_str());
        throw std::runtime_error("Error en encapsulación: " + std::string(e.what()));
    }
}

/* ---------- HANDSHAKE TLS 1.3 -- */
bool perform_tls_handshake() {
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
    tls_handshake_start = std::chrono::high_resolution_clock::now();

    if (wolfSSL_connect(ssl) != WOLFSSL_SUCCESS) {
        int error = wolfSSL_get_error(ssl, 0);
        std::cerr << "TLS 1.3 handshake falló. Error: " << error << std::endl;
        wolfSSL_free(ssl);
        return false;
    }

    tls_handshake_end = std::chrono::high_resolution_clock::now();

    auto handshake_duration = std::chrono::duration_cast<std::chrono::microseconds>(tls_handshake_end - tls_handshake_start);
    auto total_connection_time = std::chrono::duration_cast<std::chrono::milliseconds>(tls_handshake_end - connection_start);

    log_metric("TLS13_Handshake_Time_Client", handshake_duration.count(), "us");
    log_metric("WiFi_TLS13_Handshake_Latency_Client", total_connection_time.count(), "ms");

    const char* version = wolfSSL_get_version(ssl);
    const char* cipher = wolfSSL_get_cipher(ssl);
    std::cout << "TLS conectado - Version: " << version << ", Cipher: " << cipher << std::endl;

    #ifdef WOLFSSL_TLS13
    if (wolfSSL_GetVersion(ssl) == WOLFSSL_TLSV1_3) {
        log_metric("TLS13_Negotiated_Client", 1, "boolean");
        std::cout << ">> TLS 1.3 negociado exitosamente en cliente" << std::endl;
    } else {
        log_metric("TLS13_Negotiated_Client", 0, "boolean");
	std::cout << ">> Warning: Protocolo negociado: " << version << " (no TLS 1.3)" << std::endl;
    }
    #else
    log_metric("TLS13_Negotiated_Client", 0, "boolean");
    std::cout << ">> TLS 1.3 no disponible en esta compilación" << std::endl;
    #endif

    tlsSessionActive = true;
    std::cout << ">> TLS 1.3 establecido. Esperando inicio de handshake PQC..." << std::endl;
    return true;
}

/* ---------- HANDSHAKE PQC SOBRE TLS -------------------------------- */
std::vector<uint8_t> perform_pqc_handshake() {
    pqc_handshake_start = std::chrono::high_resolution_clock::now();
    
    std::cout << "\nIniciando handshake PQC sobre TLS...\n" << std::endl;

    // 1) Esperar mensaje de bienvenida PQC
    auto [welcome_type, welcome_data] = recvPQCFrame();
    if (welcome_type != PQC_WELCOME) {
        throw std::runtime_error("No se recibió mensaje de bienvenida PQC");
    }
    std::cout << "Mensaje de bienvenida PQC: " << std::string(welcome_data.begin(), welcome_data.end()) << std::endl;

    // 2) Enviar certificado cliente
    std::vector<uint8_t> cert_cli = readFile(CLI_CERT_FILE);
    std::cout << "\nEnviando certificado del cliente.\n" << std::endl;
    sendPQCFrame(PQC_CLI_CERT, cert_cli);

    // 3) Recibir certificado servidor
    auto [srv_cert_type, cert_srv] = recvPQCFrame();
    if (srv_cert_type != PQC_SRV_CERT || cert_srv.size() != SRV_CERT_LEN) {
        throw std::runtime_error("Certificado del servidor no recibido correctamente");
    }
    if (!verify_cert(cert_srv)) {
        throw std::runtime_error("Certificado del servidor inválido");
    }

    // 4) Extraer clave pública Dilithium del certificado
    int offset = CERT_BODY_SIZE - DIL_PUB;
    std::vector<uint8_t> srv_pub(cert_srv.begin() + offset, cert_srv.begin() + offset + DIL_PUB);
    std::cout << "Clave pública Dilithium extraída del certificado:" << std::endl;
    std::cout << "  Inicio: " << bytesToHex(srv_pub, 16) << std::endl;
    
    // 5) Recibir clave pública Kyber
    auto [kyb_pub_type, kyb_pub] = recvPQCFrame();
    if (kyb_pub_type != PQC_KYBER_PUB) {
        throw std::runtime_error("Clave pública Kyber no recibida correctamente");
    }

    // 6) Recibir firma Dilithium
    auto [sig_type, sig] = recvPQCFrame();
    if (sig_type != PQC_DILITHIUM_SIG) {
        throw std::runtime_error("Firma Dilithium no recibida correctamente");
    }

    std::cout << "\nVerificando firma de Kyber...\n" << std::endl;
    if (!verify_sig(srv_pub, kyb_pub, sig)) {
        throw std::runtime_error("Firma de Kyber inválida");
    }

    // 7) Encapsular y enviar ciphertext Kyber
    auto [shared_secret, ciphertext] = encapsulate(kyb_pub);
    sendPQCFrame(PQC_CTX, ciphertext);

    // 8) Esperar confirmación
    auto [ok_type, ok_data] = recvPQCFrame();
    if (ok_type != PQC_KYBER_OK) {
        throw std::runtime_error("No se recibió confirmación Kyber");
    }

    pqc_handshake_end = std::chrono::high_resolution_clock::now();
    
    auto pqc_duration = std::chrono::duration_cast<std::chrono::milliseconds>(pqc_handshake_end - pqc_handshake_start);
    auto total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(pqc_handshake_end - connection_start);
    
    log_metric("PQC_Handshake_Time_Client", pqc_duration.count(), "ms");
    log_metric("WiFi_TLS13_PQC_Total_Handshake_Latency_Client", total_duration.count(), "ms");

    pqcSessionActive = true;
    std::cout << "\nHandshake PQC completo sobre TLS.\n" << std::endl;
    return shared_secret;
}

/* ---------- RECEPCIÓN DE TEMPERATURAS PQC CON DESCIFRADO REAL ------ */
bool receive_temperatures_pqc(const std::vector<uint8_t>& shared_secret) {
    data_phase_start = std::chrono::high_resolution_clock::now();
    temp_received_count = 0;

    // USAR DIRECTAMENTE el shared secret de Kyber (igual que el servidor ESP32)
    std::cout << "Shared secret Kyber: " << bytesToHex(shared_secret, 16) << std::endl;

    std::cout << ">> Esperando temperaturas cifradas PQC sobre TLS del ESP32...\n" << std::endl;

    bool connection_active = true;
    while (connection_active && temp_received_count < 25) {
        try {
            auto decrypt_start = std::chrono::high_resolution_clock::now();
            auto [msg_type, temp_data] = recvPQCFrame(5000); // 5s timeout
            
            if (msg_type == PQC_TEMP_SEC && temp_data.size() == SEC_MSG) {
                // Extraer IV (16 bytes), ciphertext (16 bytes) y HMAC (32 bytes)
                std::vector<uint8_t> iv(temp_data.begin(), temp_data.begin() + 16);
                std::vector<uint8_t> ct(temp_data.begin() + 16, temp_data.begin() + 32);
                std::vector<uint8_t> mac(temp_data.begin() + 32, temp_data.end());

                // Verificar HMAC de IV + ciphertext usando DIRECTAMENTE shared secret
                std::vector<uint8_t> data_to_verify(temp_data.begin(), temp_data.begin() + 32);
                bool hmac_valid = verify_hmac_with_kyber_key(data_to_verify, mac, shared_secret);
                std::string hmac_status = hmac_valid ? "OK" : "FAIL";
                
                if (!hmac_valid) {
                    std::cerr << "¡HMAC inválido! Mensaje comprometido." << std::endl;
                    continue;
                }

                try {
                    // DESCIFRADO AES REAL con shared secret directo (igual que servidor)
                    std::string decrypted_text = aes_decrypt_cbc_with_kyber_key(ct, shared_secret, iv);
                    
                    auto decrypt_end = std::chrono::high_resolution_clock::now();
                    auto decrypt_duration = std::chrono::duration_cast<std::chrono::microseconds>(decrypt_end - decrypt_start);
                    log_metric("PQC_Decrypt_Receive_Client", decrypt_duration.count(), "us");

                    // Extraer temperatura del texto descifrado
                    float temperature = 0.0f;
                    if (decrypted_text.find("TEMP:") == 0) {
                        // Formato: "TEMP:25.50"
                        temperature = std::stof(decrypted_text.substr(5));
                    } else if (decrypted_text.back() == 'C') {
                        // Formato: "25.50C" (del servidor ESP32)
                        temperature = std::stof(decrypted_text.substr(0, decrypted_text.length() - 1));
                    } else {
                        // Intentar parsear directamente como número
                        try {
                            temperature = std::stof(decrypted_text);
                        } catch (const std::exception& e) {
                            std::cerr << "Formato de mensaje descifrado no reconocido: '" << decrypted_text << "'" << std::endl;
                            continue;
                        }
                    }
                    
                    temp_received_count++;
                    log_metric("Temp_Received_Count_TLS13_PQC", temp_received_count, "count");

                    // Mostrar temperatura descifrada con AES+Kyber
                    std::cout << "Temperatura PQC: " << std::fixed << std::setprecision(2) 
                             << temperature << "°C  HMAC: " << hmac_status 
                             << " (msg " << temp_received_count << "/25)" << std::endl;

                    if (temp_received_count == 25) {
                        auto data_phase_end = std::chrono::high_resolution_clock::now();
                        auto total_data_time = std::chrono::duration_cast<std::chrono::milliseconds>(data_phase_end - data_phase_start);
                        log_metric("Total_Data_Phase_Time_TLS13_PQC", total_data_time.count(), "ms");
                        log_metric("Temperature_Reception_Complete_TLS13_PQC", 25, "count");
                        std::cout << "\n>> ¡Recibidas todas las 25 temperaturas vía TLS 1.3 + PQC!" << std::endl;
                        break;
                    }
                } catch (const std::exception& e) {
                    std::cerr << "Error descifrado AES: " << e.what() << std::endl;
                    // Continuar con el siguiente mensaje
                }
            } else {
                std::cout << "Mensaje PQC no reconocido: tipo " << std::hex << (int)msg_type << std::dec << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "Error recibiendo datos PQC: " << e.what() << std::endl;
            connection_active = false;
        }
    }

    return temp_received_count == 25;
}

/* ---------- FUNCIÓN PRINCIPAL DE SESIÓN ---------------------------- */
bool session() {
    try {
        if (!connectToESP32()) {
            return false;
        }

        if (!perform_tls_handshake()) {
            return false;
        }

        auto shared_secret = perform_pqc_handshake();
        
        bool success = receive_temperatures_pqc(shared_secret);

        return success;
    } catch (const std::exception& e) {
        std::cerr << "Error en sesión: " << e.what() << std::endl;
        return false;
    }
}

/* ---------- Main --------------------------------------------------- */
int main() {
    std::cout << "Cliente TLS 1.3 + PQC HÍBRIDO Temperature RPi (Compatible ESP32 TLS+PQC)" << std::endl;

    auto program_start = std::chrono::high_resolution_clock::now();

    if (!setup_wolfssl_tls13()) {
        std::cerr << "Error en setup wolfSSL TLS 1.3" << std::endl;
        return -1;
    }

    int attempts = 0;
    const int max_attempts = 5;
    bool success = false;

    while (attempts < max_attempts && !success) {
        std::cout << "\nIntento " << (attempts + 1) << "/" << max_attempts << " (TLS 1.3 + PQC HÍBRIDO)" << std::endl;

        success = session();

        if (success) {
            std::cout << "\n✓ Recepción de temperaturas TLS 1.3 + PQC exitosa" << std::endl;
        } else {
            std::cerr << "\n✗ Error en recepción de temperaturas TLS 1.3 + PQC" << std::endl;
        }

        disconnectFromESP32();

        attempts++;
        if (attempts < max_attempts && !success) {
            std::cout << "Reintentando en 10s..." << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(10));
        }
    }

    auto program_end = std::chrono::high_resolution_clock::now();
    auto total_program_time = std::chrono::duration_cast<std::chrono::milliseconds>(program_end - program_start);
    log_metric("Total_Program_Runtime_TLS13_PQC", total_program_time.count(), "ms");

    if (ctx) {
        auto ctx_cleanup_start = std::chrono::high_resolution_clock::now();
        if (ssl) {
            wolfSSL_shutdown(ssl);
            wolfSSL_free(ssl);
        }
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
        auto ctx_cleanup_end = std::chrono::high_resolution_clock::now();

        auto ctx_cleanup_duration = std::chrono::duration_cast<std::chrono::microseconds>(ctx_cleanup_end - ctx_cleanup_start);
        log_metric("TLS13_PQC_Context_Cleanup_Client", ctx_cleanup_duration.count(), "us");
    }

    std::cout << ">> Cliente TLS 1.3 + PQC HÍBRIDO finalizado." << std::endl;

    if (success) {
        log_metric("Session_Result_TLS13_PQC", 1, "success");
        std::cout << "\n¯ Resultado: ÉXITO - 25 temperaturas TLS 1.3 + PQC recibidas correctamente" << std::endl;
    } else {
        log_metric("Session_Result_TLS13_PQC", 0, "failure");
        std::cout << "\n Resultado: FALLO - No se pudieron recibir todas las temperaturas TLS 1.3 + PQC" << std::endl;
    }

    return success ? 0 : -1;
}
