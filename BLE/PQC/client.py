import asyncio
import subprocess
from bleak import BleakClient
import os
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Dirección MAC del servidor BLE ESP32
SERVER_MAC_ADDRESS = "D0:EF:76:34:11:62"

# UUIDs correctos según el servidor
SERVICE_UUID = "12345678-1234-5678-1234-56789abcdef0"
TEMPERATURE_CHARACTERISTIC_UUID = "12345678-1234-5678-1234-56789abcdef1"
KYBER_PUBKEY_CHUNK1_UUID = "12345678-1234-5678-1234-56789abcdef2"
KYBER_PUBKEY_CHUNK2_UUID = "12345678-1234-5678-1234-56789abcdef3"
ENCRYPTED_SESSION_KEY_CHUNK1_UUID = "12345678-1234-5678-1234-56789abcdef5"
ENCRYPTED_SESSION_KEY_CHUNK2_UUID = "12345678-1234-5678-1234-56789abcdef6"

# UUIDs para los chunks de la firma de Dilithium
DILITHIUM_SIGNATURE_CHUNK1_UUID = "12345678-1234-5678-1234-56789abcdef7"
DILITHIUM_SIGNATURE_CHUNK2_UUID = "12345678-1234-5678-1234-56789abcdef8"
DILITHIUM_SIGNATURE_CHUNK3_UUID = "12345678-1234-5678-1234-56789abcdef9"
DILITHIUM_SIGNATURE_CHUNK4_UUID = "12345678-1234-5678-1234-56789abcdefA"
DILITHIUM_SIGNATURE_CHUNK5_UUID = "12345678-1234-5678-1234-56789abcdefB"

 # UUIDs para los chunks del certificado del servidor
SRV_CERT_CHUNK1_UUID = "12345678-1234-5678-1234-56789abceea0"
SRV_CERT_CHUNK2_UUID = "12345678-1234-5678-1234-56789abceea1"
SRV_CERT_CHUNK3_UUID = "12345678-1234-5678-1234-56789abceea2"
SRV_CERT_CHUNK4_UUID = "12345678-1234-5678-1234-56789abceea3"
SRV_CERT_CHUNK5_UUID = "12345678-1234-5678-1234-56789abceea4"
SRV_CERT_CHUNK6_UUID = "12345678-1234-5678-1234-56789abceea5"
SRV_CERT_CHUNK7_UUID = "12345678-1234-5678-1234-56789abceea6"
SRV_CERT_CHUNK8_UUID = "12345678-1234-5678-1234-56789abceea7"

# UUID para que el cliente suba su certificado

CLIENT_CERT_CHUNK1_UUID =  "12345678-1234-5678-1234-56789abcefab"
CLIENT_CERT_CHUNK2_UUID  = "12345678-1234-5678-1234-56789abcefac"

# Longitudes conocidas para Kyber
KYBER512_PUBLICKEY_BYTES = 800
KYBER512_CIPHERTEXT_BYTES = 768
KYBER_SHARED_SECRET_BYTES = 32

# Longitudes conocidas para Dilithium
DILITHIUM_PUBKEY_SIZE = 1312
DILITHIUM_SIG_SIZE = 2420
SIGNATURE_CHUNK_SIZE = 500
NUM_SIGNATURE_CHUNKS = 5



# Tamaños de los chunks de la clave pública de Dilithium
DILITHIUM_PUBKEY_CHUNK1_SIZE = 400
DILITHIUM_PUBKEY_CHUNK2_SIZE = 400
DILITHIUM_PUBKEY_CHUNK3_SIZE = 400
DILITHIUM_PUBKEY_CHUNK4_SIZE = 112

# Definir constantes para operaciones AES
AES_IV_BYTES = 16
AES_CIPHERTEXT_BYTES = 16  # Ajustado para mensajes pequeños
HMAC_BYTES = 32
TEMPERATURE_NOTIFICATION_BYTES = AES_IV_BYTES + AES_CIPHERTEXT_BYTES + HMAC_BYTES  # 64 bytes


#CERTIFICADO
# Longitud total del certificado del servidor (igual que en el firmware ESP32)
SRV_CERT_LEN = 3746
CERT_BODY_SIZE = 2 + 4 + 4 + 4 + DILITHIUM_PUBKEY_SIZE  # = 14 + 1312 = 1326
CERT_CHUNK_SIZE = KYBER512_CIPHERTEXT_BYTES // 2  # = 768 // 2 = 384


# Variable para almacenar la clave de sesión AES
session_key = None

# Variables globales para clave pública y mensaje
clave_publica_dilithium_global = None
mensaje_original_global = None


# Variable global para contar temperaturas
temp_count = 0

 
 
def obtener_clave_publica_dilithium():
    return clave_publica_dilithium_global

def obtener_mensaje_original():
    return mensaje_original_global

def verificar_firma_dilithium(clave_publica_dilithium, mensaje, firma):
    """
    Verifica la firma Dilithium utilizando el programa en C mediante pipes.

    recibimos:
        clave_publica_dilithium (bytes): Clave pública de Dilithium.
        mensaje (bytes): Mensaje original (clave pública Kyber).
        firma (bytes): Firma de Dilithium.

    devolvemos:
        bool: True si la firma es válida, False si no es válida, None en caso de error.
    """
    try:
        print("Verificando firma post-cuántica...")
        # Preparar los datos a enviar:
        # Orden: clave pública (1312 bytes) + longitud del mensaje (4 bytes, big endian) + mensaje + firma (2420 bytes)
        if len(clave_publica_dilithium) != DILITHIUM_PUBKEY_SIZE:
            print(f"Error: Clave pública Dilithium tiene longitud incorrecta ({len(clave_publica_dilithium)} bytes). Se esperaban {DILITHIUM_PUBKEY_SIZE} bytes.")
            return None

        if len(firma) != DILITHIUM_SIG_SIZE:
            print(f"Error: Firma Dilithium tiene longitud incorrecta ({len(firma)} bytes). Se esperaban {DILITHIUM_SIG_SIZE} bytes.")
            return None

        message_len = len(mensaje)
        if message_len > 1024:
            print(f"Error: Mensaje demasiado largo ({message_len} bytes). Máximo permitido es 1024 bytes.")
            return None

        # Convertir la longitud del mensaje a 4 bytes big endian
        msg_len_bytes = message_len.to_bytes(4, byteorder='big')

        # Concatenar todos los datos
        input_data = clave_publica_dilithium + msg_len_bytes + mensaje + firma

        # Ejecutar el programa en C y pasar los datos vía stdin
        proc = subprocess.run(
            ["./dilithium_verify"],
            input=input_data,
            capture_output=True
            # No se usa 'text=True' ya que estamos enviando bytes
        )

        # Leer la salida y el código de retorno
        return_code = proc.returncode

        # Procesar el resultado basado en el código de retorno
        if return_code == 0:
            resultado = True
        elif return_code == 1:
            print("La firma Dilithium NO es válida.")
            resultado = False
        else:
            stderr = proc.stderr.decode().strip()
            print(f"Error al verificar la firma Dilithium: {stderr}")
            resultado = None

        return resultado

    except Exception as e:
        print(f"Error al verificar la firma Dilithium: {e}")
        return None

async def verify_server_certificate(server_cert_bytes):
    """
    Verifica el certificado del servidor usando el ejecutable verify_cert.
    
    Args:
        server_cert_bytes (bytes): Certificado completo del servidor
        
    Returns:
        bool: True si el certificado es válido, False si no lo es
    """
    try:
        # Guardar el certificado en archivo temporal
        temp_cert_file = "temp_server_cert.bin"
        with open(temp_cert_file, "wb") as f:
            f.write(server_cert_bytes)
        
        # Ejecutar verify_cert con ca_pub.bin
        proc = subprocess.run(
            ["./certs/verify_server_cert", temp_cert_file, "certs/ca_pub.bin"],
            capture_output=True,
            text=True
        )
        
        # Limpiar archivo temporal
        os.remove(temp_cert_file)
        
        # Mostrar output del verificador
        if proc.stdout:
            print("Salida del verificador:")
            print(proc.stdout)
        if proc.stderr:
            print("Errores del verificador:")
            print(proc.stderr)
        
        # Retornar resultado basado en código de salida
        if proc.returncode == 0:
            return True
        else:
            print("Certificado del servidor NO VÁLIDO")
            return False
            
    except Exception as e:
        print(f"Error al verificar certificado del servidor: {e}")
        return False


def print_wolfssl_error(errorCode):
    """
    Función para imprimir errores de wolfSSL usando wc_ErrorString.
    """
    try:
        import ctypes
        from ctypes import c_int, c_char_p, create_string_buffer

        # Cargar la biblioteca wolfSSL
        wolfssl = ctypes.CDLL("libwolfssl.so")  

        # Definir la función wc_ErrorString
        wolfssl.wc_ErrorString.argtypes = [c_int, c_char_p]
        wolfssl.wc_ErrorString.restype = ctypes.c_int

        error_string = create_string_buffer(80)
        wolfssl.wc_ErrorString(errorCode, error_string)
        print(f"wolfSSL Error: {error_string.value.decode()}")
    except Exception as e:
        print(f"Error al obtener la descripción del error de wolfSSL: {e}")

def notification_handler(sender, data):
    """
    Función para procesar notificaciones BLE.
    Descifra los datos recibidos utilizando la clave de sesión AES compartida.
    """
    try:
        # Extraer el UUID de la característica que envía la notificación
        characteristic_uuid = sender.uuid.lower()
        if characteristic_uuid == TEMPERATURE_CHARACTERISTIC_UUID.lower():
            if len(data) < TEMPERATURE_NOTIFICATION_BYTES:  # IV + Ciphertext + HMAC
                print("Error: datos recibidos demasiado cortos para descifrar.")
                return

            # Calcula la longitud total del ciphertext
            ciphertext_len = len(data) - AES_IV_BYTES - HMAC_BYTES

            # Extraer IV, Ciphertext y HMAC
            iv = data[:AES_IV_BYTES]
            ciphertext = data[AES_IV_BYTES:AES_IV_BYTES + ciphertext_len]
            received_hmac = data[AES_IV_BYTES + ciphertext_len:]

            print(f"Datos recibidos: {len(data)} bytes (CT: {ciphertext_len}, HMAC: {len(received_hmac)})")

            # Verificar que la clave de sesión AES esté disponible
            if session_key is None:
                print("Error: clave de sesión AES no disponible para descifrar.")
                return

            try:
                # Crear objeto AES en modo CBC
                cipher = AES.new(session_key, AES.MODE_CBC, iv)

                # Descifrar y despadear el ciphertext
                decrypted_padded = cipher.decrypt(ciphertext)
                decrypted = unpad(decrypted_padded, AES.block_size)
                decrypted_message = decrypted.decode('utf-8')

                print(f"Temperatura descifrada: {decrypted_message}°C")
            except (ValueError, UnicodeDecodeError) as e:
                print(f"Error al despadear o decodificar el mensaje descifrado: {e}")

    except Exception as e:
        print(f"Error al procesar los datos: {e}")

#  
# 2) HANDLER para notificaciones de HANDSHAKE (Kyber + Dilithium)
#  
def handshake_notify_handler(sender, data):
    """
    Este callback se invoca tanto para:
      - KYBER_PUBKEY_CHUNK{1,2}_UUID
      - DILITHIUM_SIGNATURE_CHUNK{1..5}_UUID
    Cada vez que llegue un fragmento, lo guardamos en el buffer correspondiente.
    Cuando ya tengamos todos los bytes de la clave pública Kyber y de la firma Dilithium,
    validamos la firma y hacemos un nuevo encapsulado (nuevo handshake). 
    """
    global kyber_pubkey_buffer, dilithium_signature_buffer
    global pending_new_handshake, session_key, clave_publica_dilithium_global, mensaje_original_global

    uuid = sender.uuid.lower()
    chunk = bytes(data)  # Los bytes que llega el chunk

    #  
    #  Recibir fragmentos de la clave pública Kyber
    #  
    if uuid == KYBER_PUBKEY_CHUNK1_UUID.lower():
        print(f"[Handshake] Recibido Kyber PUBKEY Chunk1 ({len(chunk)} bytes)")
        #– Reemplazamos el buffer por si había un handshake previo incompleto
        kyber_pubkey_buffer = bytearray()
        kyber_pubkey_buffer += chunk
        return

    if uuid == KYBER_PUBKEY_CHUNK2_UUID.lower():
        print(f"[Handshake] Recibido Kyber PUBKEY Chunk2 ({len(chunk)} bytes)")
        kyber_pubkey_buffer += chunk

        # En este momento ya debemos tener 800 bytes (2×400). Verificamos longitud:
        if len(kyber_pubkey_buffer) != KYBER512_PUBLICKEY_BYTES:
            print(f"[Handshake][Error] Kyber PUBKEY total incorrecta: {len(kyber_pubkey_buffer)} bytes.")
            kyber_pubkey_buffer = bytearray()
            return
        else:
            print("[Handshake] Clave pública Kyber completa recibida (800 bytes).")

        # Guardamos el “mensaje original” (clave pública Kyber) para luego verificar la firma
        mensaje_original_global = bytes(kyber_pubkey_buffer)
        # Indicamos que estamos ahora en la fase de recibir la firma Dilithium
        pending_new_handshake = True
        # Limpia buffer de firma, por si acaso quedan bytes antiguos
        dilithium_signature_buffer = bytearray()
        return

    #  
    # 2b) Recibir fragmentos de la firma Dilithium (5 chunks)
    # 
    if uuid in [
        DILITHIUM_SIGNATURE_CHUNK1_UUID.lower(),
        DILITHIUM_SIGNATURE_CHUNK2_UUID.lower(),
        DILITHIUM_SIGNATURE_CHUNK3_UUID.lower(),
        DILITHIUM_SIGNATURE_CHUNK4_UUID.lower(),
        DILITHIUM_SIGNATURE_CHUNK5_UUID.lower()
    ]:
        # Cada chunk suele ser 500 bytes excepto el último (420 bytes).
        print(f"[Handshake] Recibido Dilithium SIG Chunk ({len(chunk)} bytes)")
        dilithium_signature_buffer += chunk

        # Cuando tengamos 2420 bytes totales, ya está completa la firma:
        if len(dilithium_signature_buffer) == DILITHIUM_SIG_SIZE:
            print("[Handshake] Firma Dilithium completa recibida (2420 bytes).")

            # 1) Verificar la firma Dilithium
            firma_valida = verificar_firma_dilithium(
                clave_publica_dilithium_global,
                mensaje_original_global,
                bytes(dilithium_signature_buffer)
            )
            if firma_valida is None:
                print("[Handshake][Error] Ocurrió un fallo interno al verificar la firma.")
                # Limpiamos buffers para volver a esperar un próximo handshake
                kyber_pubkey_buffer = bytearray()
                dilithium_signature_buffer = bytearray()
                pending_new_handshake = False
                return
            elif not firma_valida:
                print("[Handshake] ¡Firma NO válida! Ignorando este handshake.")
                kyber_pubkey_buffer = bytearray()
                dilithium_signature_buffer = bytearray()
                pending_new_handshake = False
                return

            print("[Handshake] Firma Dilithium verificada. Ahora encapsulamos para reenviar la nueva clave de sesión.")

            # 2) Encapsular un nuevo session_key con la clave pública Kyber recibida
            ciphertext_bytes, shared_secret_bytes = asyncio.get_event_loop().run_until_complete(
                encapsulate_session_key(mensaje_original_global)
            )
            if ciphertext_bytes is None or shared_secret_bytes is None:
                print("[Handshake][Error] Falló el encapsulado Kyber (no se pudo generar shared secret).")
                # Limpiar para próximos intentos
                kyber_pubkey_buffer = bytearray()
                dilithium_signature_buffer = bytearray()
                pending_new_handshake = False
                return

            # 3) Actualizar session_key (usaremos los primeros 32 bytes para AES-256)
            session_key = shared_secret_bytes[:32]
            print(f"[Handshake] Nueva clave de sesión AES establecida: {session_key.hex()}")

            # 4) Enviar el ciphertext en 2 chunks al servidor
            #    (usamos write_gatt_char dentro del event loop)
            async def _send_new_ciphertext():
                await send_encrypted_session_key(client_obj, ciphertext_bytes)

            # Por simplicidad, usamos run_until_complete para que se ejecute en el loop principal
            asyncio.get_event_loop().run_until_complete(_send_new_ciphertext())

            print("[Handshake] Rekeying completado: ciphertext reenviado al servidor.\n")

            # 5) Limpiar buffers y flags para esperar un próximo re‐handshake
            kyber_pubkey_buffer = bytearray()
            dilithium_signature_buffer = bytearray()
            pending_new_handshake = False

        return


async def read_server_certificate(client):
    """
    Lee y monta el certificado del servidor en 8 chunks.
    """
    srv_cert = bytearray()
    cert_uuids = [
        SRV_CERT_CHUNK1_UUID, SRV_CERT_CHUNK2_UUID, SRV_CERT_CHUNK3_UUID, SRV_CERT_CHUNK4_UUID,
        SRV_CERT_CHUNK5_UUID, SRV_CERT_CHUNK6_UUID, SRV_CERT_CHUNK7_UUID, SRV_CERT_CHUNK8_UUID
    ]
    for idx, uuid in enumerate(cert_uuids, 1):
        chunk = await client.read_gatt_char(uuid)
        print(f"Cert Server Chunk{idx} recibido ({len(chunk)} bytes).")
        srv_cert += chunk

    print(f"Certificado servidor recibido completo ({len(srv_cert)} bytes).")
    
    
    if len(srv_cert) != SRV_CERT_LEN:
        print(f"Error: longitud cert {len(srv_cert)} != {SRV_CERT_LEN}.")
        return None
    return bytes(srv_cert)

async def send_client_certificate(client):
    data = open("certs/cli_cert.bin", "rb").read()
    total = len(data)
    print(f"Enviando cert cliente ({total} bytes) en chunks de {CERT_CHUNK_SIZE} bytes (pares)...")

    for offset in range(0, total, CERT_CHUNK_SIZE * 2):
        chunk1 = data[offset : offset + CERT_CHUNK_SIZE]
        chunk2 = data[offset + CERT_CHUNK_SIZE : offset + CERT_CHUNK_SIZE * 2]

        # chunk #1
        await client.write_gatt_char(CLIENT_CERT_CHUNK1_UUID, chunk1, response=True)
        print(f"  Chunk1 enviado ({len(chunk1)} bytes)")

        # chunk #2 (puede ser más pequeño en la última iteración)
        if chunk2:
          await client.write_gatt_char(CLIENT_CERT_CHUNK2_UUID, chunk2, response=True)
          print(f"  Chunk2 enviado ({len(chunk2)} bytes)")

        # muy breve pausa para no saturar
        await asyncio.sleep(0.01)
    return True



def extract_dilithium_public_key_from_cert(server_cert):
    """
    Extrae la clave pública de Dilithium de un certificado ya leído.
    """
    if len(server_cert) != SRV_CERT_LEN:
        print(f"Error: longitud cert {len(server_cert)} != {SRV_CERT_LEN}.")
        return None
    
    # Offset = CERT_BODY_SIZE - DILITHIUM_PUBKEY_SIZE => 14
    offset = CERT_BODY_SIZE - DILITHIUM_PUBKEY_SIZE
    dilithium_pubkey = server_cert[offset : offset + DILITHIUM_PUBKEY_SIZE]
    print()
    print(f"-------------------------------------------------------------------")
    print(f"Extrayendo clave pública Dilithium del certificado")
    print(f"Clave Pública Dilithium extraída (offset {offset}, {len(dilithium_pubkey)} bytes).")
    
    if len(dilithium_pubkey) != DILITHIUM_PUBKEY_SIZE:
        print(f"Error: longitud dilithium pub incorrecta {len(dilithium_pubkey)} != {DILITHIUM_PUBKEY_SIZE}.")
        return None

    # Mostrar los primeros y últimos bytes como hace el cliente
    print(f"CLAVE PÚBLICA DILITHIUM: {dilithium_pubkey[:16].hex().upper()}...{dilithium_pubkey[-16:].hex().upper()} ({len(dilithium_pubkey)} BYTES)")
    
    return dilithium_pubkey


async def read_dilithium_signature(client):
    """
    Función para leer y ensamblar los chunks de la firma de Dilithium.
    """
    try:
        dilithium_signature = bytearray()

        dilithium_signature_chunks = [
            (DILITHIUM_SIGNATURE_CHUNK1_UUID, 500),
            (DILITHIUM_SIGNATURE_CHUNK2_UUID, 500),
            (DILITHIUM_SIGNATURE_CHUNK3_UUID, 500),
            (DILITHIUM_SIGNATURE_CHUNK4_UUID, 500),
            (DILITHIUM_SIGNATURE_CHUNK5_UUID, 420),
        ]

        for idx, (uuid, expected_size) in enumerate(dilithium_signature_chunks, 1):
            chunk = await client.read_gatt_char(uuid)
            print(f"Dilithium Signature Chunk{idx} recibido (longitud: {len(chunk)} bytes).")

            if len(chunk) != expected_size:
                print(f"Error: Tamaño del chunk{idx} de la firma Dilithium incorrecto ({len(chunk)} bytes). Se esperaban {expected_size} bytes.")
                return None

            dilithium_signature += chunk

        print(f"Firma completa de Dilithium recibida (longitud: {len(dilithium_signature)} bytes).")

        if len(dilithium_signature) != DILITHIUM_SIG_SIZE:
            print(f"Error: La firma completa tiene una longitud incorrecta ({len(dilithium_signature)} bytes). Se esperaban {DILITHIUM_SIG_SIZE} bytes.")
            return None

        # Imprimir la firma completa en formato hexadecimal
        firma_hex = dilithium_signature.hex()
        print(f"FIRMA DILITHIUM: {firma_hex[:16].upper()}...{firma_hex[-16:].upper()} ({len(dilithium_signature)} BYTES)")


        return bytes(dilithium_signature)
    except Exception as e:
        print(f"Error al leer la firma de Dilithium: {e}")
        return None

async def read_kyber_public_key(client):
    """
    Función para leer y combinar los fragmentos de la clave pública Kyber.
    """
    try:
        # Leer el primer fragmento de 400 bytes
        chunk1 = await client.read_gatt_char(KYBER_PUBKEY_CHUNK1_UUID)
        print(f"Chunk1 recibido (longitud: {len(chunk1)} bytes).")

        # Verificar el tamaño del primer chunk
        if len(chunk1) != 400:
            print(f"Error: Tamaño del chunk1 incorrecto ({len(chunk1)} bytes). Se esperaban 400 bytes.")
            return None

        # Leer el segundo fragmento de 400 bytes
        chunk2 = await client.read_gatt_char(KYBER_PUBKEY_CHUNK2_UUID)
        print(f"Chunk2 recibido (longitud: {len(chunk2)} bytes).")

        # Verificar el tamaño del segundo chunk
        if len(chunk2) != 400:
            print(f"Error: Tamaño del chunk2 incorrecto ({len(chunk2)} bytes). Se esperaban 400 bytes.")
            return None

        # Combinar los fragmentos
        public_key = chunk1 + chunk2
        kyber_hex = public_key.hex()
        print(f"CLAVE PÚBLICA KYBER: {kyber_hex[:16].upper()}...{kyber_hex[-16:].upper()} ({len(public_key)} BYTES)")

        if len(public_key) != KYBER512_PUBLICKEY_BYTES:
            print(f"Error: La clave pública completa tiene una longitud incorrecta ({len(public_key)} bytes). Se esperaban {KYBER512_PUBLICKEY_BYTES} bytes.")
            return None

        return public_key
    except Exception as e:
        print(f"Error al leer la clave pública Kyber: {e}")
        return None

async def encapsulate_session_key(public_key_bytes):
    """
    Función para encapsular la clave de sesión usando Kyber.
    Utiliza el ejecutable 'kyber_encapsulate' para realizar la encapsulación.

    recivimos:
        public_key_bytes (bytes): Clave pública Kyber recibida del servidor.

    devolvemos:
        tuple: (ciphertext_bytes, shared_secret_bytes) si tiene éxito, (None, None) en caso contrario.
    """
    try:
        # Guardar la clave pública en un archivo temporal para el ejecutable
        public_key_file = "kyber_public_key.bin"
        with open(public_key_file, "wb") as f:
            f.write(public_key_bytes)

        # Definir el archivo de salida para el ciphertext
        ciphertext_file = "ciphertext.bin"

        # Ejecutar el encapsulador Kyber
        proc = subprocess.run(
            ["./kyber_encapsulate", public_key_file, ciphertext_file],
            capture_output=True,
            text=True  # Capturar stdout como texto
        )

        # Eliminar el archivo temporal de la clave pública
        os.remove(public_key_file)

        if proc.returncode != 0:
            print(f"Error en la encapsulación Kyber: {proc.stderr}")
            return None, None

        # Leer el shared secret desde stdout
        shared_secret_hex = proc.stdout.strip()
        try:
            shared_secret_bytes = bytes.fromhex(shared_secret_hex)
        except ValueError:
            print("Error: Shared secret recibido no es un hexadecimal válido.")
            return None, None

        print(f"Shared Secret generado: {shared_secret_hex}")
        

        # Leer el ciphertext encapsulado desde el archivo
        with open(ciphertext_file, "rb") as f:
            ciphertext_bytes = f.read()

        # Eliminar el archivo de ciphertext
        os.remove(ciphertext_file)

        # Mostrar ciphertext en formato correcto
        ciphertext_hex = ciphertext_bytes.hex()
        print(f"CIPHERTEXT KYBER ENCAPSULADO: {ciphertext_hex[:16].upper()}...{ciphertext_hex[-16:].upper()} ({len(ciphertext_bytes)} BYTES)")

        # Verificar la longitud del ciphertext
        if len(ciphertext_bytes) != KYBER512_CIPHERTEXT_BYTES:
            print(f"Error: Longitud del ciphertext incorrecta ({len(ciphertext_bytes)} bytes). Se esperaban {KYBER512_CIPHERTEXT_BYTES} bytes.")
            return None, None

        return ciphertext_bytes, shared_secret_bytes
    except Exception as e:
        print(f"Error ejecutando kyber_encapsulate: {e}")
        return None, None

async def send_encrypted_session_key(client, encapsulated_key):
    """
    Función para enviar la clave de sesión cifrada al servidor en dos chunks.
    """
    try:
        # Dividir el ciphertext en dos chunks de 384 bytes cada uno
        chunk_size = KYBER512_CIPHERTEXT_BYTES // 2  # 384 bytes
        chunk1 = encapsulated_key[:chunk_size]
        chunk2 = encapsulated_key[chunk_size:]

        # Verificar el tamaño de los chunks
        if len(chunk1) != 384 or len(chunk2) != 384:
            print(f"Error: Tamaño de los chunks de ciphertext incorrecto.")
            return

        # Enviar el primer chunk
        await client.write_gatt_char(ENCRYPTED_SESSION_KEY_CHUNK1_UUID, chunk1, response=True)
        print("Chunk1 de la clave de sesión cifrada enviada.")

        # Enviar el segundo chunk
        await client.write_gatt_char(ENCRYPTED_SESSION_KEY_CHUNK2_UUID, chunk2, response=True)
        print("Chunk2 de la clave de sesión cifrada enviada.")
    except Exception as e:
        print(f"Error al enviar la clave de sesión cifrada: {e}")

# ─── Buffers y flags para HANDSHAKE ───────────────────────────────────
kyber_pubkey_buffer       = bytearray()
dilithium_signature_buffer = bytearray()
pending_new_handshake     = False
client_obj                = None

async def main():
    global client_obj, session_key, clave_publica_dilithium_global, mensaje_original_global

    try:
        async with BleakClient(SERVER_MAC_ADDRESS) as client:
            # 2) Asignar client_obj para usarlo luego en el handler de rekeying
            client_obj = client

            connected = await client.is_connected()
            if not connected:
                print(f"No se pudo conectar a {SERVER_MAC_ADDRESS}")
                return

            print(f"Conectado al servidor BLE: {SERVER_MAC_ADDRESS}")

            # Negociar MTU, verificar UUID de servicio, etc.
            services = await client.get_services()
            if SERVICE_UUID.lower() not in [s.uuid.lower() for s in services]:
                print(f"Servicio {SERVICE_UUID} no encontrado.")
                return

            print(f"Servicio {SERVICE_UUID} detectado.")
            print("=== Intercambio de Certificados ===")

            # ------ 1) Leer CERTIFICADO del servidor y verificarlo---------------------
            server_cert = await read_server_certificate(client)
            if server_cert is None:
                return
            print("Certificado servidor leído correctamente.")

            # --VERIFICAR CERTIFICADO del servidor ---------------------
            print("Verificando autenticidad del certificado del servidor...")
            cert_valid = await verify_server_certificate(server_cert)
            if not cert_valid:
                print("CERTIFICADO NO VÁLIDO - Abortando conexión por seguridad")
                return
            print("Certificado del servidor verificado exitosamente.")

            # ---2) Enviar CERTIFICADO del cliente ---------------------
            ok = await send_client_certificate(client)
            if not ok:
                return
            print("Certificado cliente enviado correctamente")
            print("=== Intercambio de Certificados Completado ===")
            print()
            print("Esperando handshake inicial del servidor...")
            print()

            # --------------------- 3) LEER CLAVE PÚBLICA KYBER (2 chunks) ---------------------
            print("=== Iniciando Handshake Post-Cuántico ===")
            public_key = await read_kyber_public_key(client)
            if public_key is None:
                print("No se pudo obtener la clave pública Kyber.")
                return
            mensaje_original_global = public_key

            # ---------------------4) LEER CLAVE PÚBLICA DILITHIUM (extraída del certificado)---------------------
            dilithium_pubkey = extract_dilithium_public_key_from_cert(server_cert)  # Usa certificado ya leído
            if dilithium_pubkey is None:
                print("No se pudo extraer la clave pública Dilithium.")
                return
            clave_publica_dilithium_global = dilithium_pubkey

            #--------------------- 5) LEER FIRMA DILITHIUM (5 chunks) ---------------------
            dilithium_signature = await read_dilithium_signature(client)
            if dilithium_signature is None:
                print("No se pudo recibir la firma de Dilithium.")
                return

            # 3) Verificar la firma Dilithium del handshake inicial
            es_valida = verificar_firma_dilithium(
                clave_publica_dilithium_global,
                mensaje_original_global,
                dilithium_signature
            )
            if es_valida is None:
                print("Error interno al verificar la firma Dilithium.")
                return
            elif not es_valida:
                print("Firma Dilithium no es válida. Abortando.")
                return

            print("Firma Dilithium verificada exitosamente. Continuando al encapsulado…")

            # --------------------- 6) ENCAPSULAR CLAVE SESIÓN con KYBER y ENVIAR ciphertext---------------------
            print()
            print("Generando clave de sesión...")
            ciphertext_bytes, shared_secret_bytes = await encapsulate_session_key(public_key)
            if ciphertext_bytes is None or shared_secret_bytes is None:
                print("No se pudo encapsular la clave de sesión Kyber.")
                return

            # Establecer la clave AES (los primeros 32 bytes del shared secret)
            session_key = shared_secret_bytes[:32]
            print(f"Clave de sesión AES establecida: {session_key.hex()}")
            print()
            print(f"Enviando Clave AES Encapsulada...")
            # Enviar en 2 chunks
            await send_encrypted_session_key(client, ciphertext_bytes)
            print("Ciphertext enviado al servidor.")
            print("=== Handshake Post-Cuántico Completado ===")

            # ── 7) SUSCRIBIRSE a notificaciones de TEMPERATURA y HANDSHAKES FUTUROS ─
            await client.start_notify(TEMPERATURE_CHARACTERISTIC_UUID, notification_handler)
            print("Notificaciones habilitadas para TEMPERATURA.")

            
            print("Notificaciones habilitadas para KYBER_PUBKEY chunks.")

            print("Notificaciones habilitadas para DILITHIUM_SIGNATURE chunks.")

            print("Esperando datos de temperatura y futuros rekeyings…\n")

            # ── 8) LOOP PRINCIPAL (permanecer a la escucha de notificaciones) ─────
            try:
                while True:
                    await asyncio.sleep(1)
            except KeyboardInterrupt:
                print("\nDeshabilitando notificaciones y cerrando conexión.")
                await client.stop_notify(TEMPERATURE_CHARACTERISTIC_UUID)
                 
    except Exception as e:
        print(f"Error al conectar con el dispositivo: {e}")


if __name__ == "__main__":
    asyncio.run(main())

