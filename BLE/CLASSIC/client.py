import asyncio
import subprocess
from bleak import BleakClient
import os
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Hash import HMAC, SHA256

# Dirección MAC del servidor BLE ESP32 clásico
SERVER_MAC_ADDRESS = "D0:EF:76:34:11:62"  # Cambiar por tu ESP32

# UUIDs del servidor BLE clásico (iguales al servidor wolfSSL)
SERVICE_UUID = "12345678-1234-1234-1234-123456789012"
ECDH_SERVER_PUB_UUID = "13012F01-F8C3-4F4A-A8F4-15CD926DA146"
ECDH_CLIENT_PUB_UUID = "13012F02-F8C3-4F4A-A8F4-15CD926DA146"
TEMP_CHARACTERISTIC_UUID = "87654321-4321-4321-4321-210987654321"

# Constantes ECDH
ECC_PUB_BYTES = 65    # Punto público sin comprimir SECP256R1
ECC_SHARED_BYTES = 32 # Secreto compartido
AES_KEY_BYTES = 32    # Clave AES-256

# Constantes AES/HMAC (compatibles con servidor)
AES_IV_BYTES = 16
HMAC_BYTES = 32

# Variable global para la clave de sesión AES
session_key = None
temp_count = 0

def notification_handler(sender, data):
    """
    aqui procesamos notificaciones de temperatura del servidor BLE clásico.
    Desciframos usando AES-CBC + verifica HMAC.
    """
    global temp_count, session_key
    
    try:
        characteristic_uuid = sender.uuid.lower()
        
        if characteristic_uuid == TEMP_CHARACTERISTIC_UUID.lower():
            temp_count += 1
            
            if session_key is None:
                print(f"[{temp_count}] Error: clave de sesión AES no disponible")
                return
                
            if len(data) < 48:  # Mínimo: 16 (CT) + 32 (HMAC)
                print(f"[{temp_count}] Error: datos insuficientes ({len(data)} bytes)")
                return
            
            # Extraer ciphertext y HMAC
            ciphertext = data[:-32]  # Todo menos los últimos 32 bytes
            received_hmac = data[-32:]  # Últimos 32 bytes
            
            print(f"[{temp_count}] Datos recibidos: {len(data)} bytes (CT: {len(ciphertext)}, HMAC: {len(received_hmac)})")
            
            try:
                # Verificar HMAC
                h = HMAC.new(session_key, digestmod=SHA256)
                h.update(ciphertext)
                expected_hmac = h.digest()
                
                if expected_hmac != received_hmac:
                    print(f"[{temp_count}] Error: HMAC inválido")
                    return
                
                # Descifrar con AES-CBC (IV base del servidor)
                iv = bytes([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15])
                cipher = AES.new(session_key, AES.MODE_CBC, iv)
                decrypted_padded = cipher.decrypt(ciphertext)
                decrypted = unpad(decrypted_padded, AES.block_size)
                message = decrypted.decode('utf-8')
                
                print(f"[{temp_count}] Temperatura descifrada: {message}")
                
            except Exception as e:
                print(f"[{temp_count}] Error al descifrar: {e}")
                
    except Exception as e:
        print(f"Error procesando notificación: {e}")

async def generate_ecdh_keypair():
    """Genera un par de claves ECDH usando ejecutable C con wolfSSL.
    Retorna la clave pública del cliente (65 bytes).
    """
    try:
        # Ejecutar generador de claves ECDH
        proc = subprocess.run(
            ["./ecdh_keygen"],
            capture_output=True
        )
        
        if proc.returncode != 0:
            print(f"Error generando claves ECDH: {proc.stderr.decode()}")
            return None
            
        # El ejecutable debe guardar la clave privada y retornar la pública
        if not os.path.exists("client_private_key.bin"):
            print("Error: clave privada no generada")
            return None
            
        # Leer clave pública desde stdout (hex)
        pubkey_hex = proc.stdout.decode().strip()
        try:
            client_pubkey = bytes.fromhex(pubkey_hex)
        except ValueError:
            print("Error: clave pública no es hex válido")
            return None
            
        if len(client_pubkey) != ECC_PUB_BYTES:
            print(f"Error: longitud clave pública incorrecta ({len(client_pubkey)} != {ECC_PUB_BYTES})")
            return None
            
        print(f"Par ECDH generado. Clave pública: {pubkey_hex}")
        return client_pubkey
        
    except Exception as e:
        print(f"Error ejecutando ecdh_keygen: {e}")
        return None

async def compute_shared_secret(server_pubkey):
    """
    Calcula el secreto compartido ECDH y deriva la clave AES.
    """
    try:
        # Guardar clave pública del servidor
        with open("server_public_key.bin", "wb") as f:
            f.write(server_pubkey)
            
        # Ejecutar cálculo de secreto compartido
        proc = subprocess.run(
            ["./ecdh_compute", "client_private_key.bin", "server_public_key.bin"],
            capture_output=True
        )
        
        # Limpiar archivos temporales
        os.remove("server_public_key.bin")
        if os.path.exists("client_private_key.bin"):
            os.remove("client_private_key.bin")
            
        if proc.returncode != 0:
            print(f"Error computando secreto compartido: {proc.stderr.decode()}")
            return None
            
        # Leer secreto compartido + clave AES derivada desde stdout
        output = proc.stdout.decode().strip()
        lines = output.split('\n')
        
        if len(lines) < 2:
            print("Error: salida ECDH incompleta")
            return None
            
        try:
            shared_secret = bytes.fromhex(lines[0])
            aes_key = bytes.fromhex(lines[1])
        except ValueError:
            print("Error: salida ECDH no es hex válido")
            return None
            
        if len(shared_secret) != ECC_SHARED_BYTES:
            print(f"Error: longitud secreto compartido incorrecta ({len(shared_secret)} != {ECC_SHARED_BYTES})")
            return None
            
        if len(aes_key) != AES_KEY_BYTES:
            print(f"Error: longitud clave AES incorrecta ({len(aes_key)} != {AES_KEY_BYTES})")
            return None
            
        print(f"Secreto compartido: {shared_secret.hex()}")
        print(f"Clave AES derivada: {aes_key.hex()}")
        return aes_key
        
    except Exception as e:
        print(f"Error computando secreto compartido: {e}")
        return None

async def main():
    global session_key, temp_count
    
    try:
        async with BleakClient(SERVER_MAC_ADDRESS) as client:
            connected = await client.is_connected()
            if not connected:
                print(f"No se pudo conectar a {SERVER_MAC_ADDRESS}")
                return
                
            print(f"Conectado al servidor BLE clásico: {SERVER_MAC_ADDRESS}")
            
            # Negociar MTU
            try:
                mtu = await client.request_mtu(517)
                print(f"MTU negociado: {mtu} bytes")
            except Exception as e:
                print(f"Error negociando MTU: {e}")
                
            # Verificar servicio
            services = await client.get_services()
            if SERVICE_UUID.lower() not in [s.uuid.lower() for s in services]:
                print(f"Servicio {SERVICE_UUID} no encontrado")
                return
                
            print(f"Servicio {SERVICE_UUID} detectado")
            
            # ── HANDSHAKE ECDH ──────────────────────────────────────────
            
            # 1. Generar par de claves ECDH del cliente
            print("\n=== Iniciando Handshake ECDH ===")
            client_pubkey = await generate_ecdh_keypair()
            if client_pubkey is None:
                print("Error generando claves ECDH del cliente")
                return
                
            # 2. Leer clave pública del servidor
            try:
                server_pubkey = await client.read_gatt_char(ECDH_SERVER_PUB_UUID)
                print(f"Clave pública servidor recibida: {len(server_pubkey)} bytes")
                
                if len(server_pubkey) != ECC_PUB_BYTES:
                    print(f"Error: longitud clave servidor incorrecta ({len(server_pubkey)} != {ECC_PUB_BYTES})")
                    return
                    
                print(f"Clave pública servidor: {server_pubkey.hex()}")
                
            except Exception as e:
                print(f"Error leyendo clave pública del servidor: {e}")
                return
                
            # 3. Enviar clave pública del cliente
            try:
                await client.write_gatt_char(ECDH_CLIENT_PUB_UUID, client_pubkey, response=True)
                print("Clave pública del cliente enviada")
                
            except Exception as e:
                print(f"Error enviando clave pública del cliente: {e}")
                return
                
            # 4. Computar secreto compartido y derivar clave AES
            aes_key = await compute_shared_secret(server_pubkey)
            if aes_key is None:
                print("Error computando secreto compartido")
                return
                
            session_key = aes_key
            print("=== Handshake ECDH Completado ===\n")
            
            # ── SUSCRIBIRSE A NOTIFICACIONES DE TEMPERATURA ────────────
            
            await client.start_notify(TEMP_CHARACTERISTIC_UUID, notification_handler)
            print("Suscrito a notificaciones de temperatura")
            print("Esperando temperaturas cifradas...\n")
            
            # ── LOOP PRINCIPAL ──────────────────────────────────────────
            
            try:
                while temp_count < 25:  # Esperar 25 temperaturas como el PQC
                    await asyncio.sleep(1)
                    
                print(f"\n=== Recibidas {temp_count} temperaturas ===")
                print("Desconectando...")
                
            except KeyboardInterrupt:
                print("\nInterrumpido por usuario")
                
            # Detener notificaciones
            await client.stop_notify(TEMP_CHARACTERISTIC_UUID)
            
    except Exception as e:
        print(f"Error conectando al dispositivo: {e}")

if __name__ == "__main__":
    print("=== Cliente Python BLE Clásico ===")
    print("Asegúrate de tener compilados:")
    print("  - ecdh_keygen (genera par de claves)")
    print("  - ecdh_compute (calcula secreto + deriva AES)")
    print("Conectando...\n")
    
    asyncio.run(main())
