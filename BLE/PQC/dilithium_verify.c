#include <stdio.h> 
#include <stdlib.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/version.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/dilithium.h>

// Definiciones de tamaños según Dilithium-5
#define DILITHIUM_PUBLICKEY_BYTES 1312
#define DILITHIUM_SIGNATURE_BYTES 2420
#define DILITHIUM_MESSAGE_MAX_BYTES 1024  // Ajusta según tu mensaje
#define DILITHIUM_LEVEL 2  // Nivel 2 (ML-DSA-44)

// Función para imprimir errores de wolfSSL usando wc_ErrorString
void print_wolfssl_error(int errorCode) {
    char errorString[80];
    wc_ErrorString(errorCode, errorString);  // Obtiene la descripción del error
    fprintf(stderr, "wolfSSL Error: %s\n", errorString);
}

int main() {
    // Leer la clave pública de Dilithium desde stdin
    unsigned char pubKey[DILITHIUM_PUBLICKEY_BYTES];
    size_t readBytes = fread(pubKey, 1, DILITHIUM_PUBLICKEY_BYTES, stdin);
    if (readBytes != DILITHIUM_PUBLICKEY_BYTES) {
        fprintf(stderr, "Error leyendo la clave pública Dilithium. Se esperaban %d bytes, se leyeron %zu bytes.\n",
                DILITHIUM_PUBLICKEY_BYTES, readBytes);
        return EXIT_FAILURE;
    }
    fprintf(stderr, "Clave pública Dilithium-5 leída correctamente.\n");

    // Leer la longitud del mensaje (4 bytes, big endian)
    unsigned char msgLengthBytes[4];
    readBytes = fread(msgLengthBytes, 1, 4, stdin);
    if (readBytes != 4) {
        fprintf(stderr, "Error leyendo la longitud del mensaje.\n");
        return EXIT_FAILURE;
    }
    // Convertir a tamaño (big endian)
    size_t message_len = (msgLengthBytes[0] << 24) |
                         (msgLengthBytes[1] << 16) |
                         (msgLengthBytes[2] << 8)  |
                         (msgLengthBytes[3]);

    if (message_len > DILITHIUM_MESSAGE_MAX_BYTES) {
        fprintf(stderr, "Longitud del mensaje (%zu bytes) excede el máximo permitido (%d bytes).\n",
                message_len, DILITHIUM_MESSAGE_MAX_BYTES);
        return EXIT_FAILURE;
    }

    // Leer el mensaje desde stdin
    unsigned char message[DILITHIUM_MESSAGE_MAX_BYTES];
    readBytes = fread(message, 1, message_len, stdin);
    if (readBytes != message_len) {
        fprintf(stderr, "Error leyendo el mensaje Dilithium. Se esperaban %zu bytes, se leyeron %zu bytes.\n",
                message_len, readBytes);
        return EXIT_FAILURE;
    }
    fprintf(stderr, "Mensaje Dilithium leído correctamente (longitud: %zu bytes).\n", message_len);

    // Leer la firma de Dilithium desde stdin
    unsigned char signature[DILITHIUM_SIGNATURE_BYTES];
    readBytes = fread(signature, 1, DILITHIUM_SIGNATURE_BYTES, stdin);
    if (readBytes != DILITHIUM_SIGNATURE_BYTES) {
        fprintf(stderr, "Error leyendo la firma Dilithium. Se esperaban %d bytes, se leyeron %zu bytes.\n",
                DILITHIUM_SIGNATURE_BYTES, readBytes);
        return EXIT_FAILURE;
    }
    fprintf(stderr, "Firma Dilithium-5 leída correctamente.\n");

    // Inicializar wolfSSL
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Error al inicializar wolfSSL.\n");
        return EXIT_FAILURE;
    }

    // Inicializar RNG y dilithium_key
    dilithium_key dilithiumKey;
    WC_RNG *rng;
    int ret;

    fprintf(stderr, "Inicializando RNG...\n");
    rng = wc_rng_new(NULL, 0, NULL); // nonce=NULL, nonceSz=0, heap=NULL para usar el heap predeterminado
    if (rng == NULL) {
        fprintf(stderr, "Error al asignar RNG dinámicamente.\n");
        wolfSSL_Cleanup();
        return EXIT_FAILURE;
    }

    ret = wc_InitRng(rng);
    if (ret != 0) {
        fprintf(stderr, "Error al inicializar RNG. Código: %d\n", ret);
        print_wolfssl_error(ret);
        wc_rng_free(rng);
        wolfSSL_Cleanup();
        return EXIT_FAILURE;
    }

    fprintf(stderr, "RNG inicializado correctamente.\n");

    // Inicializar la estructura dilithium_key
    fprintf(stderr, "Inicializando dilithium_key...\n");
    memset(&dilithiumKey, 0, sizeof(dilithium_key)); // Asegurar que toda la estructura esté en cero
    ret = wc_dilithium_init_ex(&dilithiumKey, NULL, INVALID_DEVID);
    if (ret != 0) {
        fprintf(stderr, "Error inicializando dilithium_key. Código: %d\n", ret);
        print_wolfssl_error(ret);
        wc_dilithium_free(&dilithiumKey);
        wc_rng_free(rng);
        wolfSSL_Cleanup();
        return EXIT_FAILURE;
    }

    fprintf(stderr, "dilithium_key inicializado correctamente.\n");

    // Establecer el nivel de Dilithium
    ret = wc_dilithium_set_level(&dilithiumKey, DILITHIUM_LEVEL);
    if (ret != 0) {
        fprintf(stderr, "Error al establecer el nivel de Dilithium. Código: %d\n", ret);
        print_wolfssl_error(ret);
        wc_dilithium_free(&dilithiumKey);
        wc_rng_free(rng);
        wolfSSL_Cleanup();
        return EXIT_FAILURE;
    }
    fprintf(stderr, "Nivel de Dilithium establecido a %d.\n", DILITHIUM_LEVEL);

    // Importar la clave pública de Dilithium
    fprintf(stderr, "Importando la clave pública Dilithium...\n");
    ret = wc_dilithium_import_public(pubKey, DILITHIUM_PUBLICKEY_BYTES, &dilithiumKey);
    if (ret != 0) {
        fprintf(stderr, "Error importando la clave pública Dilithium. Código: %d\n", ret);
        print_wolfssl_error(ret);
        wc_dilithium_free(&dilithiumKey);
        wc_rng_free(rng);
        wolfSSL_Cleanup();
        return EXIT_FAILURE;
    }

    fprintf(stderr, "Clave pública Dilithium-5 importada correctamente.\n");

    // Verificar la firma
    fprintf(stderr, "Verificando la firma Dilithium...\n");
    int verify_result = -1;
    ret = wc_dilithium_verify_msg(signature, DILITHIUM_SIGNATURE_BYTES, message, message_len, &verify_result, &dilithiumKey);
    if (ret == 0) {
        if (verify_result == 1) {
            printf("La firma Dilithium es válida.\n");
            ret = EXIT_SUCCESS;
        } else {
            printf("La firma Dilithium NO es válida.\n");
            ret = 1;
        }
    } else {
        printf("Error al verificar la firma Dilithium. Código de error: %d\n", ret);
        print_wolfssl_error(ret);
        ret = EXIT_FAILURE;
    }

    // Liberar recursos
    fprintf(stderr, "Liberando dilithium_key...\n");
    wc_dilithium_free(&dilithiumKey);
    fprintf(stderr, "dilithium_key liberado correctamente.\n");

    fprintf(stderr, "Liberando RNG...\n");
    wc_rng_free(rng);
    fprintf(stderr, "RNG liberado correctamente.\n");

    fprintf(stderr, "Limpiando wolfSSL...\n");
    wolfSSL_Cleanup();
    fprintf(stderr, "wolfSSL limpiado correctamente.\n");

    fprintf(stderr, "Programa completado correctamente.\n");

    return ret;
}
