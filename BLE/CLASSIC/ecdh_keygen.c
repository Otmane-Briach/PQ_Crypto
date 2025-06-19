/*
 * ecdh_keygen.c  
 * Genera un par de claves ECDH (SECP256R1) usando wolfSSL
 * Compilar: gcc -o ecdh_keygen ecdh_keygen.c -lwolfssl
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>        
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#define ECC_PUB_BYTES 65
#define ECC_PRIV_BYTES 32

void print_wolfssl_error(int errorCode) {
    char errorString[80];
    wc_ErrorString(errorCode, errorString);
    fprintf(stderr, "wolfSSL Error (%d): %s\n", errorCode, errorString);
}

int main() {
    WC_RNG rng;
    ecc_key clientKey;
    byte public_key[ECC_PUB_BYTES];   
    byte private_key[ECC_PRIV_BYTES]; 
    int ret;
    
    // Inicializar RNG
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        fprintf(stderr, "Error inicializando RNG: %d\n", ret);
        print_wolfssl_error(ret);
        return 1;
    }
    
    // Inicializar clave ECC
    ret = wc_ecc_init_ex(&clientKey, NULL, INVALID_DEVID);
    if (ret != 0) {
        fprintf(stderr, "Error inicializando ECC: %d\n", ret);
        print_wolfssl_error(ret);
        wc_FreeRng(&rng);
        return 1;
    }
    
    // Establecer RNG
    ret = wc_ecc_set_rng(&clientKey, &rng);
    if (ret != 0) {
        fprintf(stderr, "Warning: wc_ecc_set_rng falló: %d\n", ret);
    }
    
    // Generar par de claves ECDH (SECP256R1 = 32 bytes)
    ret = wc_ecc_make_key(&rng, 32, &clientKey);
    if (ret != 0) {
        fprintf(stderr, "Error generando claves ECC: %d\n", ret);
        print_wolfssl_error(ret);
        wc_ecc_free(&clientKey);
        wc_FreeRng(&rng);
        return 1;
    }
    
    // Exportar clave pública (formato x963 sin comprimir)
    word32 pubLen = ECC_PUB_BYTES;
    ret = wc_ecc_export_x963(&clientKey, public_key, &pubLen);
    if (ret != 0 || pubLen != ECC_PUB_BYTES) {
        fprintf(stderr, "Error exportando clave pública: %d, longitud: %u\n", ret, pubLen);
        if (ret != 0) print_wolfssl_error(ret);
        wc_ecc_free(&clientKey);
        wc_FreeRng(&rng);
        return 1;
    }
    
    // Exportar clave privada 
    word32 privLen = ECC_PRIV_BYTES;
    ret = wc_ecc_export_private_only(&clientKey, private_key, &privLen);
    if (ret != 0 || privLen != ECC_PRIV_BYTES) {
        fprintf(stderr, "Error exportando clave privada: %d, longitud: %u\n", ret, privLen);
        if (ret != 0) print_wolfssl_error(ret);
        wc_ecc_free(&clientKey);
        wc_FreeRng(&rng);
        return 1;
    }
    
    // Guardar clave privada en archivo
    FILE *priv_file = fopen("client_private_key.bin", "wb");
    if (!priv_file) {
        fprintf(stderr, "Error creando archivo de clave privada\n");
        wc_ecc_free(&clientKey);
        wc_FreeRng(&rng);
        return 1;
    }
    
    if (fwrite(private_key, 1, ECC_PRIV_BYTES, priv_file) != ECC_PRIV_BYTES) {
        fprintf(stderr, "Error escribiendo clave privada\n");
        fclose(priv_file);
        wc_ecc_free(&clientKey);
        wc_FreeRng(&rng);
        return 1;
    }
    fclose(priv_file);
    
    // Imprimir clave pública en hex por stdout
    for (int i = 0; i < ECC_PUB_BYTES; i++) {
        printf("%02x", public_key[i]);
    }
    printf("\n");
    
    // Limpiar recursos
    wc_ecc_free(&clientKey);
    wc_FreeRng(&rng);
    
    return 0;
}
