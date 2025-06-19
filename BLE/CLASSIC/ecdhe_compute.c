/*
 * ecdh_compute.c 
 * Computa el secreto compartido ECDH y deriva clave AES con SHA256
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#define ECC_PUB_BYTES 65
#define ECC_PRIV_BYTES 32
#define ECC_SHARED_BYTES 32
#define AES_KEY_BYTES 32

static const byte SHA256_INFO[] = "ble-ecdh-aes";

// Imprime el mensaje de error asociado a un código de error de wolfSSL
void print_wolfssl_error(int errorCode) {
    char errorString[80];
    wc_ErrorString(errorCode, errorString);
    fprintf(stderr, "wolfSSL Error (%d): %s\n", errorCode, errorString);
}

// Carga una clave privada desde un archivo binario
int load_private_key(const char* filename, byte* private_key) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Error abriendo archivo de clave privada: %s\n", filename);
        return -1;
    }
    
    if (fread(private_key, 1, ECC_PRIV_BYTES, file) != ECC_PRIV_BYTES) {
        fprintf(stderr, "Error leyendo clave privada\n");
        fclose(file);
        return -1;
    }
    fclose(file);
    return 0;
}

// Carga una clave pública desde un archivo binario
int load_public_key(const char* filename, byte* public_key) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Error abriendo archivo de clave pública: %s\n", filename);
        return -1;
    }
    
    if (fread(public_key, 1, ECC_PUB_BYTES, file) != ECC_PUB_BYTES) {
        fprintf(stderr, "Error leyendo clave pública\n");
        fclose(file);
        return -1;
    }
    fclose(file);
    return 0;
}

// Deriva una clave AES a partir de un secreto compartido usando SHA-256
int derive_aes_key(const byte* shared_secret, byte* aes_key) {
    wc_Sha256 sha;
    int ret;
    
    ret = wc_InitSha256(&sha);
    if (ret != 0) {
        fprintf(stderr, "Error inicializando SHA256: %d\n", ret);
        print_wolfssl_error(ret);
        return ret;
    }
    
    wc_Sha256Update(&sha, shared_secret, ECC_SHARED_BYTES);
    wc_Sha256Update(&sha, SHA256_INFO, sizeof(SHA256_INFO) - 1);
    
    ret = wc_Sha256Final(&sha, aes_key);
    wc_Sha256Free(&sha);
    
    if (ret != 0) {
        fprintf(stderr, "Error finalizando SHA256: %d\n", ret);
        print_wolfssl_error(ret);
        return ret;
    }
    
    return 0;
}


int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Uso: %s <client_private_key.bin> <server_public_key.bin>\n", argv[0]);
        return 1;
    }
    
    WC_RNG rng;
    ecc_key clientKey, serverKey;
    byte client_private[ECC_PRIV_BYTES];
    byte server_public[ECC_PUB_BYTES];
    byte shared_secret[ECC_SHARED_BYTES];
    byte aes_key[AES_KEY_BYTES];
    int ret;
    
    // Cargar claves desde archivos
    if (load_private_key(argv[1], client_private) < 0) {
        return 1;
    }
    
    if (load_public_key(argv[2], server_public) < 0) {
        return 1;
    }
    
    // Inicializar RNG PRIMERO
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        fprintf(stderr, "Error inicializando RNG: %d\n", ret);
        print_wolfssl_error(ret);
        return 1;
    }
    
    // Inicializar clave del cliente
    ret = wc_ecc_init_ex(&clientKey, NULL, INVALID_DEVID);
    if (ret != 0) {
        fprintf(stderr, "Error inicializando ECC cliente: %d\n", ret);
        print_wolfssl_error(ret);
        wc_FreeRng(&rng);
        return 1;
    }
    
    // importanteeee: Establecer RNG en la clave del cliente ANTES de importar
    ret = wc_ecc_set_rng(&clientKey, &rng);
    if (ret != 0) {
        fprintf(stderr, "Error estableciendo RNG en clave cliente: %d\n", ret);
        print_wolfssl_error(ret);
        wc_ecc_free(&clientKey);
        wc_FreeRng(&rng);
        return 1;
    }
    
    // Importar clave privada del cliente
    ret = wc_ecc_import_private_key(client_private, ECC_PRIV_BYTES, NULL, 0, &clientKey);
    if (ret != 0) {
        fprintf(stderr, "Error importando clave privada: %d\n", ret);
        print_wolfssl_error(ret);
        wc_ecc_free(&clientKey);
        wc_FreeRng(&rng);
        return 1;
    }
    
    // Inicializar clave del servidor
    ret = wc_ecc_init_ex(&serverKey, NULL, INVALID_DEVID);
    if (ret != 0) {
        fprintf(stderr, "Error inicializando ECC servidor: %d\n", ret);
        print_wolfssl_error(ret);
        wc_ecc_free(&clientKey);
        wc_FreeRng(&rng);
        return 1;
    }
    
    // CRUCIAL: Establecer RNG en la clave del servidor ANTES de importar
    ret = wc_ecc_set_rng(&serverKey, &rng);
    if (ret != 0) {
        fprintf(stderr, "Error estableciendo RNG en clave servidor: %d\n", ret);
        print_wolfssl_error(ret);
        wc_ecc_free(&serverKey);
        wc_ecc_free(&clientKey);
        wc_FreeRng(&rng);
        return 1;
    }
    
    // Importar clave pública del servidor
    ret = wc_ecc_import_x963(server_public, ECC_PUB_BYTES, &serverKey);
    if (ret != 0) {
        fprintf(stderr, "Error importando clave pública servidor: %d\n", ret);
        print_wolfssl_error(ret);
        wc_ecc_free(&serverKey);
        wc_ecc_free(&clientKey);
        wc_FreeRng(&rng);
        return 1;
    }
    
    // Computar secreto compartido ECDH
    word32 outlen = ECC_SHARED_BYTES;
    ret = wc_ecc_shared_secret(&clientKey, &serverKey, shared_secret, &outlen);
    if (ret != 0 || outlen != ECC_SHARED_BYTES) {
        fprintf(stderr, "Error computando secreto compartido: %d, longitud: %u\n", ret, outlen);
        if (ret != 0) print_wolfssl_error(ret);
        wc_ecc_free(&serverKey);
        wc_ecc_free(&clientKey);
        wc_FreeRng(&rng);
        return 1;
    }
    
    // Derivar clave AES con SHA256
    ret = derive_aes_key(shared_secret, aes_key);
    if (ret != 0) {
        wc_ecc_free(&serverKey);
        wc_ecc_free(&clientKey);
        wc_FreeRng(&rng);
        return 1;
    }
    
    // Imprimir resultados en hex (línea 1: secreto, línea 2: AES key)
    for (int i = 0; i < ECC_SHARED_BYTES; i++) {
        printf("%02x", shared_secret[i]);
    }
    printf("\n");
    
    for (int i = 0; i < AES_KEY_BYTES; i++) {
        printf("%02x", aes_key[i]);
    }
    printf("\n");
    
    // Limpiar recursos
    wc_ecc_free(&serverKey);
    wc_ecc_free(&clientKey);
    wc_FreeRng(&rng);
    
    return 0;
}
