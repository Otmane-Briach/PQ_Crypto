#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/version.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/dilithium.h>

// Parámetros Dilithium
#define DILITHIUM_LEVEL             2
#define DILITHIUM_PUBLICKEY_BYTES 1312
#define DILITHIUM_PRIVKEY_BYTES   2560

// Función de error
void print_wolfssl_error(int errorCode) {
    char errorString[80];
    wc_ErrorString(errorCode, errorString);
    fprintf(stderr, "wolfSSL Error: %s\n", errorString);
}

int main(void)
{
    int ret;
    WC_RNG dilithiumRng;
    dilithium_key caKey;

    // 1. Inicializar wolfSSL
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Error inicializando wolfSSL\n");
        return EXIT_FAILURE;
    }

    // 2. Inicializar RNG para Dilithium
    if ((ret = wc_InitRng(&dilithiumRng)) != 0) {
        fprintf(stderr, "Error inicializando RNG: %d\n", ret);
        print_wolfssl_error(ret);
        goto cleanup_ssl;
    }

    // 3. Inicializar estructura Dilithium
    wc_dilithium_init(&caKey);

    // 4. Establecer nivel de seguridad
    if ((ret = wc_dilithium_set_level(&caKey, DILITHIUM_LEVEL)) != 0) {
        fprintf(stderr, "Error setting Dilithium level: %d\n", ret);
        print_wolfssl_error(ret);
        goto cleanup_rng;
    }

    // 5. Generar par de claves CA
    if ((ret = wc_dilithium_make_key(&caKey, &dilithiumRng)) != 0) {
        fprintf(stderr, "Error generando claves Dilithium (CA): %d\n", ret);
        print_wolfssl_error(ret);
        goto cleanup_key;
    }

    // 6. Exportar clave privada
    {
        FILE *fp = fopen("ca_priv.bin", "wb");
        if (!fp) { perror("fopen ca_priv.bin"); goto cleanup_key; }
        word32 sz = DILITHIUM_PRIVKEY_BYTES;
        byte *buf = malloc(sz);
        if ((ret = wc_dilithium_export_private(&caKey, buf, &sz)) != 0) {
            fprintf(stderr, "Error exportando clave privada: %d\n", ret);
            print_wolfssl_error(ret);
            free(buf);
            fclose(fp);
            goto cleanup_key;
        }
        fwrite(buf, 1, sz, fp);
        fclose(fp);
        free(buf);
        fprintf(stderr, "CA private key written to ca_priv.bin (%u bytes)\n", sz);
    }

    // 7. Exportar clave pública
    {
        FILE *fp = fopen("ca_pub.bin", "wb");
        if (!fp) { perror("fopen ca_pub.bin"); goto cleanup_key; }
        word32 sz = DILITHIUM_PUBLICKEY_BYTES;
        byte *buf = malloc(sz);
        if ((ret = wc_dilithium_export_public(&caKey, buf, &sz)) != 0) {
            fprintf(stderr, "Error exportando clave pública: %d\n", ret);
            print_wolfssl_error(ret);
            free(buf);
            fclose(fp);
            goto cleanup_key;
        }
        fwrite(buf, 1, sz, fp);
        fclose(fp);
        free(buf);
        fprintf(stderr, "CA public key written to ca_pub.bin (%u bytes)\n", sz);
    }

cleanup_key:
    wc_dilithium_free(&caKey);
cleanup_rng:
    wc_FreeRng(&dilithiumRng);
cleanup_ssl:
    wolfSSL_Cleanup();
    return (ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
