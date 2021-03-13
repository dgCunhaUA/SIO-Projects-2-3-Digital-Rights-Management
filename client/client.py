#!/usr/bin/env python
import requests
import logging
import binascii
import json
import os
import subprocess
import time
import sys
import random
import secrets
import base64

from cryptography.hazmat.primitives import hashes, serialization, cmac
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, load_der_public_key, ParameterFormat
from cryptography.hazmat.primitives.asymmetric import dsa, rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key, load_der_private_key, load_pem_parameters
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import uuid
from cryptography.hazmat.primitives import hashes, hmac
from cryptography import x509

from cryptography.hazmat.primitives.asymmetric import padding as paddingAsymetric
import PyKCS11
import binascii


logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

SERVER_URL = 'http://127.0.0.1:8080'

def encrypt_AES(key, info, modo):
    if modo == "CBC":
        iv = os.urandom(16)
        blocksize = 16

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(blocksize*8).padder()
        
        info = padder.update(info) + padder.finalize()
        data_encrypted = encryptor.update(info) + encryptor.finalize()

        return data_encrypted, iv

    elif modo == "GCM":
        iv = os.urandom(12)
        
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
        ).encryptor()

        encryptor.authenticate_additional_data(b'associated_data')
        data_encrypted = encryptor.update(info) + encryptor.finalize()

        return data_encrypted, iv, encryptor.tag
    else:
        print("ERRO")
        sys.exit(0)


def encrypt_ChaCha20(key, info):
    nonce = os.urandom(16)

    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None)
    encryptor = cipher.encryptor()
    data_encrypted = encryptor.update(info)
    return data_encrypted, nonce

def decrypt_AES(key, iv, data_encrypted, modo, tag=None):
    if modo == "CBC":
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()

        data =  decryptor.update(data_encrypted) + decryptor.finalize()
        data = unpadder.update(data) + unpadder.finalize()

        return data

    elif modo == "GCM":
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
        ).decryptor()

        decryptor.authenticate_additional_data(b'associated_data')
        return decryptor.update(data_encrypted) + decryptor.finalize()
    else:
        print("Erro")
        sys.exit(0)

def decrypt_ChaCha20(key, nonce, data_encrypted):
    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None)
    decryptor = cipher.decryptor()
    info = decryptor.update(data_encrypted)

    return info

def client_sign(digest_c, data):
    with open("Client_Certificate.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
        
    with open("Client_Certificate.crt", "rb") as cert_file:
        client_cert = cert_file.read()


    if digest_c == "SHA256":
        signature = private_key.sign(
            data.encode(),
            paddingAsymetric.PSS(
                mgf=paddingAsymetric.MGF1(hashes.SHA256()),          
                salt_length=paddingAsymetric.PSS.MAX_LENGTH
                ),
                hashes.SHA256()           
            )
    elif digest_c == "SHA512":
        signature = private_key.sign(
            data.encode(),
            paddingAsymetric.PSS(
                mgf=paddingAsymetric.MGF1(hashes.SHA512()),          
                salt_length=paddingAsymetric.PSS.MAX_LENGTH
                ),
                hashes.SHA512()   
            )
    else:
        print("Erro")                                        
        return "Erro"

    return signature


def verify_signature(server_cert, signature):

    return True


def main(uuid_c):
    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")

    # Get a list of media files
    print("Contacting Server")
    
    CLIENT_CIPHERSUITS = ["AES256_CBC_SHA256", "AES256_CBC_SHA512", "AES256_GCM_SHA256", "AES256_GCM_SHA512", "ChaCha20_None_SHA256", "ChaCha20_None_SHA512"]

    lib ='/usr/local/lib/libpteidpkcs11.so'
    pkcs11 = PyKCS11.PyKCS11Lib()
    pkcs11.load(lib)
    slots = pkcs11.getSlotList()
    slot = slots[0]
    session = pkcs11.openSession(slot)

    obj = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
                                        (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION CERTIFICATE')])[0]
    all_atributes = [PyKCS11.CKA_VALUE]
    attributes = session.getAttributeValue(obj, all_atributes)[0]
    cert = x509.load_der_x509_certificate(bytes(attributes))
    cc_cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)


    cc_private_key = session.findObjects([(
                PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                (PyKCS11.CKA_LABEL,'CITIZEN AUTHENTICATION KEY')])[0]


    mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)
    
    data = {"uuid": uuid_c, "client_ciphersuits": CLIENT_CIPHERSUITS, "cc_cert": cc_cert_pem.decode('latin')}        
    data = json.dumps(data)
    signature = bytes(session.sign(cc_private_key, data, mechanism))


    payload = {"data": data, "signature": base64.b64encode(signature).decode('latin')}
    req = requests.get(f'{SERVER_URL}/api/protocols', data= json.dumps(payload))
    req = req.json()

    data_signed = json.loads(req["data"])
    algorithms_modes_digests = data_signed["ciphersuit"].split("_")
    
    algorithm = algorithms_modes_digests[0]
    mode = algorithms_modes_digests[1]
    digest_c = algorithms_modes_digests[2]

    signature = base64.b64decode(req["signature"].encode())

    with open("Certification_Authority.crt", "rb") as CA_cert_file:
        CA_cert = x509.load_pem_x509_certificate(CA_cert_file.read())
        CA_public_key = CA_cert.public_key()

    server_cert = x509.load_pem_x509_certificate(data_signed["server_cert"].encode())
    server_public_key_rsa = server_cert.public_key()

    #Verificar o certificado                                                                                                                       
    CA_public_key.verify(
        server_cert.signature,
        server_cert.tbs_certificate_bytes,
        paddingAsymetric.PKCS1v15(),
        server_cert.signature_hash_algorithm,
    )

    #verificar assinatura
    if digest_c == "SHA256":
        server_public_key_rsa.verify(
            signature,
            req["data"].encode(),
            paddingAsymetric.PSS(
                mgf=paddingAsymetric.MGF1(hashes.SHA256()), 
                salt_length=paddingAsymetric.PSS.MAX_LENGTH
            ),
            hashes.SHA256()         
        )
    elif digest_c == "SHA512":
        server_public_key_rsa.verify(
            signature,
            req["data"].encode(),
            paddingAsymetric.PSS(
                mgf=paddingAsymetric.MGF1(hashes.SHA512()),
                salt_length=paddingAsymetric.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )
    else:
        print("Erro")
        sys.exit(0)

    #Certificados do client e private key
    with open("Client_Certificate.pem", "rb") as key_file:
        client_cert_private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

    with open("Client_Certificate.crt", "rb") as cert_file:
        client_cert = cert_file.read()

    data = json.dumps({ "uuid_c": uuid_c, "client_cert": client_cert.decode('latin') })
    
    
    signature = client_sign(digest_c, data)
    payload = { "data": data, "signature": base64.b64encode(signature).decode('latin')}
    req = requests.get(f'{SERVER_URL}/api/key', data=json.dumps(payload))
    req = req.json()

    signature = base64.b64decode(req["signature"].encode())
    message = req["message"].encode()

    req = json.loads(message)

    #Verificar o certificado     
    CA_public_key.verify(
        server_cert.signature,
        server_cert.tbs_certificate_bytes,
        paddingAsymetric.PKCS1v15(),
        server_cert.signature_hash_algorithm,
    )

    #Verificar a assinatura
    if digest_c == "SHA256":
        server_public_key_rsa.verify(
            signature,
            message,
            paddingAsymetric.PSS(
                mgf=paddingAsymetric.MGF1(hashes.SHA256()), 
                salt_length=paddingAsymetric.PSS.MAX_LENGTH
            ),
            hashes.SHA256()         
        )
    elif digest_c == "SHA512":
        server_public_key_rsa.verify(
            signature,
            message,
            paddingAsymetric.PSS(
                mgf=paddingAsymetric.MGF1(hashes.SHA512()),
                salt_length=paddingAsymetric.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )
    else:
        print("Erro")
        sys.exit(0)

    
    parameters_pem = req["parameters"].encode()
    server_pub_key_pem = req["server_pub_key"].encode()

    server_pub_key = load_pem_public_key(server_pub_key_pem)
    parameters = load_pem_parameters(parameters_pem)

    client_private_key = parameters.generate_private_key()
    client_pub_key_pem = client_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

    client_shared_key = client_private_key.exchange(server_pub_key)    
    if digest_c == "SHA256":
        shared_key_derived = HKDF(  
            algorithm=hashes.SHA256(), 
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(client_shared_key)
    elif digest_c == "SHA512":
        shared_key_derived = HKDF(  
            algorithm=hashes.SHA512(), 
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(client_shared_key)
    else:
        print("Erro ao derivar a shared key")
        sys.exit(0)   

    data = {"uuid": uuid_c, "client_pub_key": client_pub_key_pem.decode('utf-8')}
    data = json.dumps(data)
    signature = client_sign(digest_c, data)

    payload = {"data": data, "signature": base64.b64encode(signature).decode('latin') }
    req = requests.post(url=f'{SERVER_URL}/api/shared_key', data=json.dumps(payload))


    req = requests.get(f'{SERVER_URL}/api/list')
    if req.status_code == 200:
        print("Got Server List")

    media_list = req.json()

    # Present a simple selection menu    
    idx = 0
    print("MEDIA CATALOG\n")
    for item in media_list:
        print(f'{idx} - {media_list[idx]["name"]}')
    print("----")

    while True:
        selection = input("Select a media file number (q to quit): ")
        if selection.strip() == 'q':
            sys.exit(0)

        if not selection.isdigit():
            continue

        selection = int(selection)
        if 0 <= selection < len(media_list):
            break

    # Example: Download first file
    media_item = media_list[selection]          
    print(f"Playing {media_item['name']}")

    # Detect if we are running on Windows or Linux
    # You need to have ffplay or ffplay.exe in the current folder
    # In alternative, provide the full path to the executable
    if os.name == 'nt':
        proc = subprocess.Popen(['ffplay.exe', '-i', '-'], stdin=subprocess.PIPE)
    else:
        proc = subprocess.Popen(['ffplay', '-i', '-'], stdin=subprocess.PIPE)

    
    # Get data from server and send it to the ffplay stdin through a pipe
    for chunk in range(media_item['chunks'] + 1):

        if algorithm == "AES256":
            if mode == "CBC":
                media_id, iv = encrypt_AES(shared_key_derived, media_item["id"].encode(), "CBC")
                iv = base64.b64encode(iv).decode('latin')
                
                chunk, iv2 = encrypt_AES(shared_key_derived, str(chunk).encode(), "CBC")
                iv2 = base64.b64encode(iv2).decode('latin')

                info = json.dumps({"uuid": uuid_c, "iv": iv, "iv2": iv2})

            elif mode == "GCM":
                media_id, iv, tag1 = encrypt_AES(shared_key_derived, media_item["id"].encode(), "GCM")
                iv = base64.b64encode(iv).decode('latin')
                tag1 = base64.b64encode(tag1).decode('latin')
                
                chunk, iv2, tag2 = encrypt_AES(shared_key_derived, str(chunk).encode(), "GCM")
                iv2 = base64.b64encode(iv2).decode('latin')
                tag2 = base64.b64encode(tag2).decode('latin')

                info = json.dumps({"uuid": uuid_c, "iv": iv, "iv2": iv2, "tag1": tag1, "tag2": tag2})

        elif algorithm == "ChaCha20":
            media_id, nonce = encrypt_ChaCha20(shared_key_derived, media_item["id"].encode())
            nonce = base64.b64encode(nonce).decode('latin')

            chunk, nonce2 = encrypt_ChaCha20(shared_key_derived, str(chunk).encode())
            nonce2 = base64.b64encode(nonce2).decode('latin')
            
            info = json.dumps({"uuid": uuid_c, "nonce": nonce, "nonce_chunk": nonce2})
        else:
            print("erro")
            sys.exit(0)

        media_id = base64.urlsafe_b64encode(media_id).decode('latin')
        chunk = base64.urlsafe_b64encode(chunk).decode('latin')

        signature = client_sign(digest_c, info)
        payload = { "data": info, "signature": base64.b64encode(signature).decode('latin') }

        req = requests.get(f'{SERVER_URL}/api/download?id={media_id}&chunk={chunk}', data=json.dumps(payload))
        req = req.json()

        signature = base64.b64decode(req["signature"].encode())
        #verificar assinatura
        if digest_c == "SHA256":
            server_public_key_rsa.verify(
                signature,
                req["data"].encode(),
                paddingAsymetric.PSS(
                    mgf=paddingAsymetric.MGF1(hashes.SHA256()), 
                    salt_length=paddingAsymetric.PSS.MAX_LENGTH
                ),
                hashes.SHA256()         
            )
        elif digest_c == "SHA512":
            server_public_key_rsa.verify(
                signature,
                req["data"].encode(),
                paddingAsymetric.PSS(
                    mgf=paddingAsymetric.MGF1(hashes.SHA512()),
                    salt_length=paddingAsymetric.PSS.MAX_LENGTH
                ),
                hashes.SHA512()
            )
        else:
            print("Erro")
            sys.exit(0)
        
        req = json.loads(req["data"])

        if algorithm == "AES256":               
            try:
                data_encrypted = req["data"].encode()
                data_encrypted = base64.b64decode(data_encrypted)            
                iv = req["iv"].encode()
                iv = base64.b64decode(iv)
                MAC = req["MAC"].encode()
                MAC = base64.b64decode(MAC)       
                salt = req["salt"].encode()
                salt = base64.b64decode(salt)
            except:
                print(req["error"])
                proc.kill()
                break
                return 0
            
            if digest_c == "SHA256":
                kdf = PBKDF2HMAC(                      
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                key = kdf.derive(shared_key_derived) 
            elif digest_c == "SHA512":
                kdf = PBKDF2HMAC(                      
                    algorithm=hashes.SHA512(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                key = kdf.derive(shared_key_derived) 
            else:
                print("Erro")
                sys.exit(0)

            c = cmac.CMAC(algorithms.AES(key))
            c.update(data_encrypted)
            c.verify(MAC)

            if mode == "CBC":
                data = decrypt_AES(key, iv, data_encrypted, "CBC")
            elif mode == "GCM":
                tag = req["tag"].encode()
                tag = base64.b64decode(tag)
                data = decrypt_AES(key, iv, data_encrypted, "GCM", tag)

        
            info = json.loads(data.decode('latin'))

            data = info["data"]
            data = binascii.a2b_base64(data)
            

        elif algorithm == "ChaCha20":                                                   #CHACHA20 Funciona
            try:
                nonce = req["nonce"].encode()
                nonce = base64.b64decode(nonce)
                data_encrypted = req["data"].encode()
                data_encrypted = base64.b64decode(data_encrypted)
                MAC = req["MAC"].encode()
                MAC = base64.b64decode(MAC)
                salt = req["salt"].encode()
                salt = base64.b64decode(salt)
                
            except:
                print(req["error"])
                proc.kill()
                break
                return 0

            if digest_c == "SHA256":
                kdf = PBKDF2HMAC(                       
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                key = kdf.derive(shared_key_derived)

                h = hmac.HMAC(key, hashes.SHA256())
                h.update(data_encrypted)
                h.verify(MAC)
            elif digest_c == "SHA512":
                kdf = PBKDF2HMAC(                      
                    algorithm=hashes.SHA512(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                key = kdf.derive(shared_key_derived)

                h = hmac.HMAC(key, hashes.SHA512())
                h.update(data_encrypted)
                h.verify(MAC)

            else:
                print("ERRO")
                sys.exit(0)

            data = decrypt_ChaCha20(key, nonce, data_encrypted)
            info = json.loads(data.decode('latin'))

            data = info["data"]
            data = binascii.a2b_base64(data)
        else:
            print("Erro")
            sys.exit(0)


        try:
            proc.stdin.write(data)
        except:
            break

if __name__ == '__main__':
    uuid_c = str(uuid.uuid1())
    while True:
        main(uuid_c)
        time.sleep(1)