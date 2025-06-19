#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/version.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/kyber.h>
#include <wolfssl/wolfcrypt/wc_kyber.h>

// Definiciones de tamaños según Kyber-512
#define KYBER512_PUBLICKEY_BYTES 800
#define KYBER512_CIPHERTEXT_BYTES 768
#define KYBER_SHARED_SECRET_BYTES 32

#ifndef INVALID_DEVID
    #define INVALID_DEVID -1 // Consistencia con el servidor
#endif

// Función para imprimir errores de wolfSSL usando wc_ErrorString
void print_wolfssl_error(int errorCode) {
    char errorString[80];
    wc_ErrorString(errorCode, errorString);  // Obtiene la descripción del error
    fprintf(stderr, "wolfSSL Error: %s\n", errorString);
}

int main(int argc, char* argv[]) {
    // Verificar argumentos
    if (argc != 3) {
        fprintf(stderr, "Uso: %s <clave_publica_kyber_bin> <ciphertext_salida_bin>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Obtenemos los parámetros
    const char* public_key_file = argv[1];
    const char* ciphertext_output_file = argv[2];

    // Abrimos el archivo de clave pública
    FILE* pubKeyFile = fopen(public_key_file, "rb");
    if (!pubKeyFile) {
        fprintf(stderr, "No se pudo abrir el archivo de clave pública: %s\n", public_key_file);
        return EXIT_FAILURE;
    }

    // Leer la clave pública desde el archivo binario
    unsigned char pubKey[KYBER512_PUBLICKEY_BYTES];
    size_t readBytes = fread(pubKey, 1, KYBER512_PUBLICKEY_BYTES, pubKeyFile);
    fclose(pubKeyFile);

    if (readBytes != KYBER512_PUBLICKEY_BYTES) {
        fprintf(stderr,
                "Error leyendo la clave pública Kyber. "
                "Se esperaban %d bytes, se leyeron %zu bytes.\n",
                KYBER512_PUBLICKEY_BYTES, readBytes);
        return EXIT_FAILURE;
    }

    fprintf(stderr, "Clave pública Kyber-512 leída correctamente.\n");

    // Inicializar wolfSSL
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Error al inicializar wolfSSL.\n");
        return EXIT_FAILURE;
    }

    // Inicializar RNG y KyberKey
    KyberKey kyberKey;
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

    // Inicializar la estructura KyberKey
    fprintf(stderr, "Inicializando KyberKey...\n");
    memset(&kyberKey, 0, sizeof(KyberKey)); // Asegurar que toda la estructura esté en cero
    ret = wc_KyberKey_Init(WC_ML_KEM_512, &kyberKey, NULL, INVALID_DEVID);
    if (ret != 0) {
        fprintf(stderr, "Error inicializando KyberKey. Código: %d\n", ret);
        print_wolfssl_error(ret);
        wc_KyberKey_Free(&kyberKey);
        wc_rng_free(rng);
        wolfSSL_Cleanup();
        return EXIT_FAILURE;
    }

    fprintf(stderr, "KyberKey inicializado correctamente.\n");

    // Decodificar la clave pública Kyber
    fprintf(stderr, "Decodificando la clave pública Kyber...\n");
    ret = wc_KyberKey_DecodePublicKey(&kyberKey, pubKey, KYBER512_PUBLICKEY_BYTES);
    if (ret != 0) {
        fprintf(stderr, "Error decodificando la clave pública Kyber. Código: %d\n", ret);
        print_wolfssl_error(ret);
        wc_KyberKey_Free(&kyberKey);
        wc_rng_free(rng);
        wolfSSL_Cleanup();
        return EXIT_FAILURE;
    }

    fprintf(stderr, "Clave pública Kyber-512 decodificada correctamente.\n");

    // Preparar buffers para ciphertext y shared secret
    unsigned char ciphertext[KYBER512_CIPHERTEXT_BYTES];
    unsigned char shared_secret[KYBER_SHARED_SECRET_BYTES];

    fprintf(stderr, "Encapsulando la clave de sesión AES...\n");

    // Encapsular la clave de sesión AES
    ret = wc_KyberKey_Encapsulate(&kyberKey, ciphertext, shared_secret, rng);
    if (ret != 0) {
        fprintf(stderr, "Error encapsulando la clave de sesión AES. Código: %d\n", ret);
        print_wolfssl_error(ret);
        wc_KyberKey_Free(&kyberKey);
        wc_rng_free(rng);
        wolfSSL_Cleanup();
        return EXIT_FAILURE;
    }

    fprintf(stderr, "Encapsulación completada correctamente.\n");

    // Escribir el ciphertext encapsulado a un archivo binario
    fprintf(stderr, "Escribiendo ciphertext encapsulado a: %s\n", ciphertext_output_file);
    FILE* ctFile = fopen(ciphertext_output_file, "wb");
    if (!ctFile) {
        fprintf(stderr, "No se pudo abrir el archivo de salida para el ciphertext: %s\n",
                ciphertext_output_file);
        wc_KyberKey_Free(&kyberKey);
        wc_rng_free(rng);
        wolfSSL_Cleanup();
        return EXIT_FAILURE;
    }

    size_t written = fwrite(ciphertext, 1, KYBER512_CIPHERTEXT_BYTES, ctFile);
    fclose(ctFile);

    if (written != KYBER512_CIPHERTEXT_BYTES) {
        fprintf(stderr, "Error escribiendo el ciphertext encapsulado en el archivo.\n");
        wc_KyberKey_Free(&kyberKey);
        wc_rng_free(rng);
        wolfSSL_Cleanup();
        return EXIT_FAILURE;
    }

    fprintf(stderr, "Ciphertext encapsulado escrito correctamente en el archivo: %s\n",
           ciphertext_output_file);

    // Imprimir el shared secret en formato hexadecimal (solo en stdout)
    for (int i = 0; i < KYBER_SHARED_SECRET_BYTES; i++) {
        printf("%02X", shared_secret[i]);
    }
    printf("\n");  

    // Liberar recursos
    fprintf(stderr, "Liberando KyberKey...\n");
    wc_KyberKey_Free(&kyberKey);   
    fprintf(stderr, "KyberKey liberado correctamente.\n");

    fprintf(stderr, "Liberando RNG...\n");
    wc_rng_free(rng);  
    fprintf(stderr, "RNG liberado correctamente.\n");

    fprintf(stderr, "Limpiando wolfSSL...\n");
    wolfSSL_Cleanup();
    fprintf(stderr, "wolfSSL limpiado correctamente.\n");

    fprintf(stderr, "Programa completado correctamente.\n");

    return EXIT_SUCCESS;
}
