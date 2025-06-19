#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/version.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/dilithium.h>

#include "cert_defs.h"   

#define DILITHIUM_LEVEL 2

static byte* load_file(const char* path, size_t* len) {
    FILE* f = fopen(path, "rb");
    if (!f) { perror(path); return NULL; }
    fseek(f, 0, SEEK_END);
    long l = ftell(f);
    rewind(f);
    if (l < 0) { perror("ftell"); fclose(f); return NULL; }
    byte* buf = malloc(l);
    if (!buf) {
        fprintf(stderr, "ERROR: fallo malloc de %ld bytes\n", l);
        fclose(f);
        return NULL;
    }
    if (fread(buf, 1, l, f) != (size_t)l) {
        fprintf(stderr, "ERROR: fallo fread %s\n", path);
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *len = (size_t)l;
    return buf;
}

static void print_wolfssl_error(int e) {
    char err[80];
    wc_ErrorString(e, err);
    fprintf(stderr, "ERROR: wolfSSL: %s (code %d)\n", err, e);
}

int verify_server_cert(const char* cert_path, const char* ca_pub_path) {
    int    result = 1;
    size_t cert_len = 0, ca_len = 0;
    byte*  cert_buf = NULL;
    byte*  ca_buf   = NULL;
    WC_RNG      rng;
    dilithium_key caKey;

    // --- 1) Cargar archivos ---
    fprintf(stderr, "\nCargando archivos\n");
    cert_buf = load_file(cert_path, &cert_len);
    if (!cert_buf) goto cleanup;
    if (cert_len < CERT_BODY_SIZE + 1) {
        fprintf(stderr, "ERROR: Certificado demasiado pequeño (%zu bytes)\n", cert_len);
        goto cleanup;
    }
    ca_buf = load_file(ca_pub_path, &ca_len);
    if (!ca_buf) goto cleanup;

    fprintf(stderr, "OK: Cargado '%s' (%zu bytes) y '%s' (%zu bytes)\n",
            cert_path, cert_len, ca_pub_path, ca_len);

    // --- 2) Parsear cuerpo y firma ---
    CertBody* body = (CertBody*)cert_buf;
    byte*     sig  = cert_buf + CERT_BODY_SIZE;
    size_t    sig_sz = cert_len - CERT_BODY_SIZE;

    // --- 3) Validación de fechas ---
    fprintf(stderr, "\nValidando fechas\n");
    time_t now_t = time(NULL);
    time_t nb_t  = (time_t)ntohl(body->valid_not_before);
    time_t na_t  = (time_t)ntohl(body->valid_not_after);

    char nb_str[20], na_str[20], now_str[20];
    struct tm tm_buf;

    localtime_r(&nb_t, &tm_buf);
    strftime(nb_str, sizeof(nb_str), "%Y-%m-%d %H:%M:%S", &tm_buf);
    localtime_r(&na_t, &tm_buf);
    strftime(na_str, sizeof(na_str), "%Y-%m-%d %H:%M:%S", &tm_buf);
    localtime_r(&now_t, &tm_buf);
    strftime(now_str, sizeof(now_str), "%Y-%m-%d %H:%M:%S", &tm_buf);

    fprintf(stderr,
        "  Válido desde : %s\n"
        "  Válido hasta : %s\n"
        "  Ahora        : %s\n",
        nb_str, na_str, now_str);

    if (now_t < nb_t || now_t > na_t) {
        fprintf(stderr, "FAIL: Certificado fuera del periodo de validez\n");
        goto cleanup;
    }
    fprintf(stderr, "Periodo de validez OK\n");

    // --- 4) Inicializar wolfSSL y RNG ---
    fprintf(stderr, "\nInicializando wolfSSL y RNG\n");
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: wolfSSL_Init fallo\n");
        goto cleanup;
    }
    if (wc_InitRng(&rng) != 0) {
        fprintf(stderr, "ERROR: wc_InitRng fallo\n");
        goto cleanup_ssl;
    }
    fprintf(stderr, "OK: wolfSSL y RNG inicializados\n");

    // --- 5) Importar clave pública de la CA ---
    fprintf(stderr, "\nImportando clave pública de la CA\n");
    wc_dilithium_init(&caKey);
    if (wc_dilithium_set_level(&caKey, DILITHIUM_LEVEL) != 0) {
        print_wolfssl_error(-1);
        goto cleanup_rng;
    }
    if (wc_dilithium_import_public(ca_buf, (word32)ca_len, &caKey) != 0) {
        fprintf(stderr, "ERROR: wc_dilithium_import_public fallo\n");
        goto cleanup_rng;
    }
    fprintf(stderr, "OK: Clave pública de la CA importada\n");

    // --- 6) Verificar firma ---
    fprintf(stderr, "\nVerificando firma (%zu bytes)\n", sig_sz);
    int verify_ok = 0;
    if (wc_dilithium_verify_msg(sig, (word32)sig_sz,
                                (byte*)body, CERT_BODY_SIZE,
                                &verify_ok, &caKey) != 0) {
        fprintf(stderr, "ERROR: wc_dilithium_verify_msg fallo\n");
        goto cleanup_rng;
    }
    if (!verify_ok) {
        fprintf(stderr, "FAIL: Firma NO válida\n");
        goto cleanup_rng;
    }
    fprintf(stderr, "OK: Firma válida\n");

    // --- 7) Mostrar ID del dispositivo ---
    fprintf(stderr, "\nDetalles del certificado\n");
    fprintf(stderr, "  ID del dispositivo: %u\n", ntohl(body->device_id));

    result = 0;  // éxito

cleanup_rng:
    wc_FreeRng(&rng);
cleanup_ssl:
    wolfSSL_Cleanup();
cleanup:
    if (cert_buf) free(cert_buf);
    if (ca_buf)   free(ca_buf);
    wc_dilithium_free(&caKey);
    return result;
}

int main(int argc, char** argv) {
    if (argc != 3) {
        fprintf(stderr, "Uso: %s <server_cert.bin> <ca_pub.bin>\n", argv[0]);
        return EXIT_FAILURE;
    }
    return verify_server_cert(argv[1], argv[2]) == 0
         ? EXIT_SUCCESS
         : EXIT_FAILURE;
}
