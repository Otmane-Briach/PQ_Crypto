#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include "cert_defs.h"  // Definiciones de CertBody y CERT_BODY_SIZE

// Parámetros Dilithium
#define DILITHIUM_LEVEL             2
#define DILITHIUM_PUBLICKEY_BYTES 1312
#define DILITHIUM_PRIVKEY_BYTES   2560
#define DILITHIUM_SIGNATURE_BYTES 2420

void print_err(int e) {
    char buf[80];
    wc_ErrorString(e, buf);
    fprintf(stderr, "wolfSSL Error: %s\n", buf);
}

int main(int argc, char** argv) {
    if (argc != 3) {
        fprintf(stderr, "Uso: %s <device_id> <output_prefix>\n", argv[0]);
        return EXIT_FAILURE;
    }
    uint32_t device_id = (uint32_t)strtoul(argv[1], NULL, 10);
    const char* outp = argv[2];

    int ret = 0;
    WC_RNG       rng;
    dilithium_key caKey, srvKey;
    CertBody      body;
    byte          sig[DILITHIUM_SIGNATURE_BYTES];
    word32        sigSz = DILITHIUM_SIGNATURE_BYTES;

    // 1) Inicializar wolfSSL + RNG
    if ((ret = wolfSSL_Init()) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Error wolfSSL_Init: %d\n", ret);
        return EXIT_FAILURE;
    }
    if ((ret = wc_InitRng(&rng)) != 0) {
        fprintf(stderr, "Error wc_InitRng: %d\n", ret);
        print_err(ret);
        wolfSSL_Cleanup();
        return EXIT_FAILURE;
    }

    // 2) Cargar e inicializar CA privkey
    wc_dilithium_init_ex(&caKey, NULL, INVALID_DEVID);
    if ((ret = wc_dilithium_set_level(&caKey, DILITHIUM_LEVEL)) != 0) {
        fprintf(stderr, "Error set_level CA: %d\n", ret);
        print_err(ret);
        goto cleanup_rng;
    }
    {
        FILE* f = fopen("ca_priv.bin", "rb");
        if (!f) { perror("fopen ca_priv.bin"); ret = 1; goto cleanup_ca; }
        byte buf[DILITHIUM_PRIVKEY_BYTES];
        if (fread(buf, 1, DILITHIUM_PRIVKEY_BYTES, f) != DILITHIUM_PRIVKEY_BYTES) {
            fprintf(stderr, "Error leyendo ca_priv.bin\n");
            fclose(f);
            ret = 1;
            goto cleanup_ca;
        }
        fclose(f);
        if ((ret = wc_dilithium_import_private(buf, DILITHIUM_PRIVKEY_BYTES, &caKey)) != 0) {
            fprintf(stderr, "Error import_private CA: %d\n", ret);
            print_err(ret);
            goto cleanup_ca;
        }
    }

    // 3) Generar par de claves del servidor
    wc_dilithium_init(&srvKey);
    if ((ret = wc_dilithium_set_level(&srvKey, DILITHIUM_LEVEL)) != 0) {
        fprintf(stderr, "Error set_level SRV: %d\n", ret);
        print_err(ret);
        goto cleanup_srv;
    }
    if ((ret = wc_dilithium_make_key(&srvKey, &rng)) != 0) {
        fprintf(stderr, "Error make_key SRV: %d\n", ret);
        print_err(ret);
        goto cleanup_srv;
    }

    // 4) Exportar srv_priv.bin
    {
        char filename[64];
        snprintf(filename, sizeof(filename), "%s_priv.bin", outp);
        FILE* f = fopen(filename, "wb");
        if (!f) { perror("fopen srv_priv.bin"); ret = 1; goto cleanup_srv; }
        word32 sz = DILITHIUM_PRIVKEY_BYTES;
        byte* buf = malloc(sz);
        wc_dilithium_export_private_der(&srvKey, buf, &sz);
        fwrite(buf, 1, sz, f);
        fclose(f);
        free(buf);
        fprintf(stderr, "Wrote %s_priv.bin (%u bytes)\n", outp, sz);
    }

    // 5) Rellenar CertBody
    body.version          = htons(1);
    body.device_id        = htonl(device_id);
    body.valid_not_before = htonl((uint32_t)time(NULL));
    body.valid_not_after  = htonl((uint32_t)(time(NULL) + 3600*24*365));  // 1 año
    {
        word32 pkSz = DILITHIUM_PUBLICKEY_BYTES;
        wc_dilithium_export_public(&srvKey, body.pubkey, &pkSz);
    }

    // 6) Firmar body con CA
    ret = wc_dilithium_sign_msg(
        (byte*)&body, CERT_BODY_SIZE,
        sig, &sigSz,
        &caKey, &rng
    );
    if (ret) {
        fprintf(stderr, "Error sign_msg: %d\n", ret);
        print_err(ret);
        goto cleanup_srv;
    }

    // 7) Volcar srv_cert.bin = body || signature
    {
        char filename[64];
        snprintf(filename, sizeof(filename), "%s_cert.bin", outp);
        FILE* f = fopen(filename, "wb");
        if (!f) { perror("fopen srv_cert.bin"); ret = 1; goto cleanup_srv; }
        fwrite(&body, 1, CERT_BODY_SIZE, f);
        fwrite(sig,    1, sigSz,          f);
        fclose(f);
        fprintf(stderr, "Wrote %s_cert.bin (%u+%u bytes)\n",
                outp, (unsigned)CERT_BODY_SIZE, (unsigned)sigSz);
    }

cleanup_srv:
    wc_dilithium_free(&srvKey);
cleanup_ca:
    wc_dilithium_free(&caKey);
cleanup_rng:
    wc_FreeRng(&rng);
    wolfSSL_Cleanup();
    return (ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
