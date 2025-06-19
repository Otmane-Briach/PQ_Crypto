#include <stdio.h>
#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha256.h>
 
#define HMAC_LENGTH 32
#define AES_IV_BYTES 16
#define AES_CIPHERTEXT_BYTES 16
#define TOTAL_BYTES (AES_IV_BYTES + AES_CIPHERTEXT_BYTES + HMAC_LENGTH)

int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Uso: %s <clave_aes_hex>\n", argv[0]);
        return 1;
    }

    const char* aes_hex = argv[1];
    if (strlen(aes_hex) != 64) { // 32 bytes en hex
        fprintf(stderr, "Error: La clave AES debe tener 64 caracteres hexadecimales (32 bytes).\n");
        return 1;
    }

    //vamos a convertir la cadena hexadecimal (aes_hex) de 64 caracteres en un arreglo de 32 bytes (session_key).
    unsigned char session_key[32];
    for (int i = 0; i < 32; i++) {
        char byte_str[3] = { aes_hex[2*i], aes_hex[2*i + 1], '\0' };
        session_key[i] = (unsigned char)strtol(byte_str, NULL, 16);
    }

    // Inicializar la biblioteca
    wolfSSL_Init();

    // Leer los datos cifrados + HMAC de la entrada estándar
    unsigned char buffer[1024];
    size_t readLen = fread(buffer, 1, sizeof(buffer), stdin);

    if (readLen != TOTAL_BYTES) { 
        fprintf(stderr, "Error: Input debe ser exactamente %d bytes (16 IV + 32 Ciphertext + 32 HMAC)\n", TOTAL_BYTES);
        return 1;
    }

    // Extraer IV, Ciphertext y HMAC
    unsigned char IV[16];
    memcpy(IV, buffer, AES_IV_BYTES);
    unsigned char* encrypted = buffer + AES_IV_BYTES;
    unsigned char* received_hmac = buffer + AES_IV_BYTES + AES_CIPHERTEXT_BYTES;

    // Verificar HMAC
    Hmac hmac;
    unsigned char calculated_hmac[HMAC_LENGTH];
    if (wc_HmacInit(&hmac, NULL, INVALID_DEVID) != 0) {
        fprintf(stderr, "Error: Fallo al inicializar HMAC\n");
        return 1;
    }

    if (wc_HmacSetKey(&hmac, WC_SHA256, session_key, sizeof(session_key)) != 0) {
        fprintf(stderr, "Error: Fallo al establecer la clave HMAC\n");
        wc_HmacFree(&hmac);
        return 1;
    }

    // Incluir el IV en el HMAC
    if (wc_HmacUpdate(&hmac, IV, AES_IV_BYTES) != 0) {
        fprintf(stderr, "Error: Fallo al actualizar HMAC con IV\n");
        wc_HmacFree(&hmac);
        return 1;
    }

    // Incluir el ciphertext en el HMAC
    if (wc_HmacUpdate(&hmac, encrypted, AES_CIPHERTEXT_BYTES) != 0) {
        fprintf(stderr, "Error: Fallo al actualizar HMAC con ciphertext\n");
        wc_HmacFree(&hmac);
        return 1;
    }

    if (wc_HmacFinal(&hmac, calculated_hmac) != 0) {
        fprintf(stderr, "Error: Fallo al finalizar HMAC\n");
        wc_HmacFree(&hmac);
        return 1;
    }

    //########################################################
            // Imprimir el IV
        fprintf(stderr, "IV: ");
        for (size_t i = 0; i < AES_IV_BYTES; i++) {
            fprintf(stderr, "%02x", IV[i]); // Imprime cada byte en formato hexadecimal con dos dígitos
        }
        fprintf(stderr, "\n");

        // Imprimir el ciphertext
        fprintf(stderr, "Ciphertext: ");
        for (size_t i = 0; i < AES_CIPHERTEXT_BYTES; i++) {
            fprintf(stderr, "%02x", encrypted[i]); // Imprime cada byte del ciphertext en hexadecimal
        }
        fprintf(stderr, "\n");

        // Imprimir la clave usada para HMAC
        fprintf(stderr, "Clave HMAC: ");
        for (size_t i = 0; i < sizeof(session_key); i++) {
            fprintf(stderr, "%02x", session_key[i]); // Imprime cada byte de la clave en hexadecimal
        }
        fprintf(stderr, "\n");



    //#########################################################


    wc_HmacFree(&hmac);

    // Debug: Imprimir hashes para comparación
    fprintf(stderr, "Calculated HMAC: ");
    for(int i = 0; i < HMAC_LENGTH; i++) {
        fprintf(stderr, "%02x", calculated_hmac[i]);
    }
    fprintf(stderr, "\nReceived HMAC:   ");
    for(int i = 0; i < HMAC_LENGTH; i++) {
        fprintf(stderr, "%02x", received_hmac[i]);
    }
    fprintf(stderr, "\n");

    if (memcmp(calculated_hmac, received_hmac, HMAC_LENGTH) != 0) {
        fprintf(stderr, "Error: HMAC inválido\n");
        return 1;
    }

    // Descifrar AES-CBC
    Aes aes;
    if (wc_AesInit(&aes, NULL, 0) != 0) {
        fprintf(stderr, "Error: Fallo al inicializar AES\n");
        return 1;
    }

    if (wc_AesSetKey(&aes, session_key, sizeof(session_key), IV, AES_DECRYPTION) != 0) {
        fprintf(stderr, "Error: Fallo al establecer la clave AES\n");
        wc_AesFree(&aes);
        return 1;
    }

    unsigned char decrypted[AES_CIPHERTEXT_BYTES] = {0};
    if (wc_AesCbcDecrypt(&aes, decrypted, encrypted, AES_CIPHERTEXT_BYTES) != 0) { // 32 bytes ciphertext
        fprintf(stderr, "Error: Fallo al descifrar\n");
        wc_AesFree(&aes);
        return 1;
    }

    wc_AesFree(&aes);

    // Manejar padding PKCS7
    unsigned char paddingLen = decrypted[AES_CIPHERTEXT_BYTES - 1]; // Último byte
    if (paddingLen == 0 || paddingLen > 16) {
        fprintf(stderr, "Error: Padding inválido.\n");
        return 1;
    }

    size_t message_length = AES_CIPHERTEXT_BYTES - paddingLen;
    if (message_length > sizeof(decrypted)) {
        fprintf(stderr, "Error: Longitud del mensaje descifrado inválida.\n");
        return 1;
    }

    // Escribir resultado a stdout
    fwrite(decrypted, 1, message_length, stdout);

    return 0;
}
