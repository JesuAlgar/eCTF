#!/usr/bin/env python3
"""
encoder.py
----------
Implementa la clase Encoder para generar frames cifrados con AES-CTR y firmarlos con HMAC.
"""

import argparse
import struct
import json
import base64
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class Encoder:
    def __init__(self, secrets: bytes):
        """
        Inicializa el Encoder con los secretos.
        :param secrets: Contenido del archivo de secretos generado por gen_secrets.
        """
        secrets_dict = json.loads(secrets)
        self.master_key = base64.b64decode(secrets_dict["master_key"])
        self.channel_keys = {int(k): base64.b64decode(v) for k, v in secrets_dict["channel_keys"].items()}
        self.mac_key = base64.b64decode(secrets_dict["mac_key"])
        self.seq_numbers = {}

    def encode(self, channel: int, frame: bytes, timestamp: int) -> bytes:
        """
        Codifica un frame aplicando AES-CTR y generando un HMAC.
        :param channel: Canal (uint32).
        :param frame: Contenido del frame.
        :param timestamp: Timestamp (uint64).
        :returns: Frame codificado como bytes.
        """
        # Validar canal: si no se encuentra y no es emergencia (0), error.
        if channel not in self.channel_keys and channel != 0:
            raise ValueError("Invalid channel")
        # Usar la clave específica para el canal o la master key para el canal 0
        channel_key = self.channel_keys.get(channel, self.master_key)
        seq_num = self.seq_numbers.get(channel, 0) + 1
        self.seq_numbers[channel] = seq_num
        # Generar nonce de 16 bytes: 4 bytes de channel, 8 bytes de timestamp y 4 bytes de seq_num.
        nonce = struct.pack("<IQI", channel, timestamp, seq_num)
        # Encriptar usando AES-CTR
        cipher = Cipher(algorithms.AES(channel_key), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        # Rellenar el frame a 64 bytes si es necesario.
        padded_frame = frame.ljust(64, b'\0')
        encrypted_frame = encryptor.update(padded_frame) + encryptor.finalize()
        # Generar HMAC para autenticación
        h = hmac.new(self.mac_key, digestmod=hashlib.sha256)
        h.update(struct.pack("<IQ", channel, timestamp))
        h.update(encrypted_frame)
        frame_mac = h.digest()
        # Estructura final: channel (4 bytes) | timestamp (8 bytes) | encrypted_frame (64 bytes) | mac (32 bytes) | seq_num (8 bytes)
        return struct.pack("<IQ", channel, timestamp) + encrypted_frame + frame_mac + struct.pack("<Q", seq_num)

def main():
    parser = argparse.ArgumentParser(prog="ectf25_design.encoder")
    parser.add_argument("secrets_file", type=argparse.FileType("rb"), help="Path to the secrets file")
    parser.add_argument("channel", type=int, help="Channel to encode for")
    parser.add_argument("frame", help="Contents of the frame")
    parser.add_argument("timestamp", type=int, help="64-bit timestamp to use")
    args = parser.parse_args()
    encoder = Encoder(args.secrets_file.read())
    encoded = encoder.encode(args.channel, args.frame.encode(), args.timestamp)
    print(repr(encoded))

if __name__ == "__main__":
    main()
