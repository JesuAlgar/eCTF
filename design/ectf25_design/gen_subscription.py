#!/usr/bin/env python3
"""
gen_subscription.py
-------------------
Genera el código de suscripción para un decodificador usando la clave específica por canal.
El formato de la suscripción será de 52 bytes, formado por:
   - Payload (36 bytes):
       • decoder_id   (4 bytes, uint32)
       • start        (4 bytes, uint32)
       • end          (4 bytes, uint32)
       • channel      (4 bytes, uint32)
       • encoder_id   (4 bytes, uint32)
       • partial_key  (16 bytes)
   - MAC (16 bytes): Calculado usando AES-CMAC sobre el payload usando la clave específica del canal.
"""

import argparse
import json
import struct
import base64
from pathlib import Path
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.backends import default_backend

def aes_cmac_python(key: bytes, data: bytes) -> bytes:
    """
    Calcula AES-CMAC sobre 'data' usando 'key' y devuelve 16 bytes.
    """
    c = CMAC(algorithms.AES(key), backend=default_backend())
    c.update(data)
    return c.finalize()

def gen_subscription(secrets: bytes, decoder_id: int, start: int, end: int, channel: int, encoder_id: int) -> bytes:
    """
    Genera el contenido seguro de suscripción.
    
    Parámetros:
      - secrets: Contenido del archivo JSON generado por gen_secrets.py.
      - decoder_id: ID del decoder (por ejemplo, 1).
      - start: Timestamp de inicio (uint32).
      - end: Timestamp de fin (uint32).
      - channel: Canal a suscribir.
      - encoder_id: ID del encoder.
      
    Retorna:
      - Datos de suscripción de 52 bytes: payload (36 bytes) + MAC (16 bytes).
    """
    secrets_dict = json.loads(secrets)
    
    # Validar que el canal sea válido (se espera que secrets_dict["channels"] contenga los canales permitidos)
    if channel not in secrets_dict["channels"]:
        raise ValueError(f"Invalid channel: {channel}")
    
    # Obtener la clave específica del canal
    channel_keys = {int(k): base64.b64decode(v) for k, v in secrets_dict["channel_keys"].items()}
    if channel not in channel_keys:
        raise ValueError("Channel key not found")
    channel_key = channel_keys[channel]
    
    # Obtener la partial key para este decodificador a partir de secrets_dict["partial_keys"]
    partial_keys = secrets_dict.get("partial_keys", {})
    key_name = f"decoder_{decoder_id}"
    if key_name not in partial_keys:
        raise ValueError(f"Partial key not found for {key_name}")
    partial_key = base64.b64decode(partial_keys[key_name])
    if len(partial_key) != 16:
        raise ValueError("Partial key must be 16 bytes")
    
    # Empaquetar el payload de suscripción: decoder_id, start, end, channel, encoder_id, partial_key.
    payload = struct.pack("<IIIII16s", decoder_id, start, end, channel, encoder_id, partial_key)
    if len(payload) != 36:
        raise ValueError("Payload length is not 36 bytes")
    
    # Calcular MAC usando AES-CMAC con la clave específica del canal
    mac = aes_cmac_python(channel_key, payload)
    if len(mac) != 16:
        raise ValueError("MAC length is not 16 bytes")
    
    # Concatenar payload y MAC para obtener 52 bytes.
    subscription_packet = payload + mac
    return subscription_packet

def parse_args():
    parser = argparse.ArgumentParser(
        description="Genera el código de suscripción para un decodificador."
    )
    parser.add_argument("--force", "-f", action="store_true",
                        help="Sobreescribir archivo de suscripción existente.")
    parser.add_argument("secrets_file", type=argparse.FileType("rb"),
                        help="Ruta al archivo de secretos creado por gen_secrets.py")
    parser.add_argument("subscription_file", type=Path,
                        help="Archivo de salida para la suscripción")
    parser.add_argument("decoder_id", type=int, help="ID del decoder (por ejemplo, 1)")
    parser.add_argument("start", type=lambda x: int(x, 0), help="Timestamp de inicio (uint32)")
    parser.add_argument("end", type=lambda x: int(x, 0), help="Timestamp de fin (uint32)")
    parser.add_argument("channel", type=int, help="Canal a suscribir")
    parser.add_argument("encoder_id", type=int, help="ID del encoder")
    return parser.parse_args()

def main():
    args = parse_args()
    try:
        subscription = gen_subscription(args.secrets_file.read(), args.decoder_id, args.start, args.end, args.channel, args.encoder_id)
    except Exception as e:
        print(f"Generate subscription {args.channel} failed!")
        raise e
    
    mode = "wb" if args.force else "xb"
    with open(args.subscription_file, mode) as f:
        f.write(subscription)
    print(f"Wrote subscription to {str(args.subscription_file.absolute())}")

if __name__ == "__main__":
    main()
