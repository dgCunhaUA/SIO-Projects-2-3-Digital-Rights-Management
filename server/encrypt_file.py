#!/usr/bin/env python

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import cryptography.hazmat.backends as backends
import base64
import binascii
from cryptography.hazmat.primitives import padding, hashes, serialization, cmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import json
from getpass import getpass



key = key_to_files = getpass()

salt = os.urandom(16)

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA512(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backends.default_backend()
)
key = kdf.derive(key.encode())

nonce = os.urandom(16)
cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=backends.default_backend())
encryptor = cipher.encryptor()

#encrypt
song_file = open("server/catalog/898a08080d1840793122b7e118b27a95d117ebce_non_encrypted.mp3", "rb")     #som nao encriptado
writer_encrypted_song = open("server/catalog/898a08080d1840793122b7e118b27a95d117ebce.mp3", "wb")       #som encriptado

with open("server/catalog/898a08080d1840793122b7e118b27a95d117ebce_nonce_salt", "wb") as nonce_salt_writer:
    nonce = base64.b64encode(nonce).decode('latin')
    salt = base64.b64encode(salt).decode('latin')
    json_data = json.dumps({"nonce": nonce, "salt": salt}).encode('latin')
    nonce_salt_writer.write(json_data)
    

blocksize = 4096
while True:
    chunk = song_file.read(blocksize)
    if chunk:
        if len(chunk)!=blocksize:
            ct = encryptor.update(chunk) + encryptor.finalize()
        else:
            ct = encryptor.update(chunk)

        writer_encrypted_song.write(ct)

    else:
        break


song_file.close()
nonce_salt_writer.close()
writer_encrypted_song.close()