#!/usr/bin/env python
from cryptography.hazmat.primitives import hashes, serialization, cmac
from cryptography.hazmat.primitives.asymmetric import dh, dsa, rsa, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, load_pem_public_key, load_pem_private_key, load_der_private_key, load_der_parameters,ParameterFormat, load_pem_parameters
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding as paddingAsymetric
from twisted.web import server, resource
from twisted.internet import reactor, defer
import logging
import binascii
import json
import os
import math
import base64
import random
import secrets
from cryptography.hazmat.primitives import padding
import sys
from getpass import getpass


logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.DEBUG)

CATALOG = { '898a08080d1840793122b7e118b27a95d117ebce': 
            {
                'name': 'Sunny Afternoon - Upbeat Ukulele Background Music',
                'album': 'Upbeat Ukulele Background Music',
                'description': 'Nicolai Heidlas Music: http://soundcloud.com/nicolai-heidlas',
                'duration': 3*60+33,
                'file_name': '898a08080d1840793122b7e118b27a95d117ebce.mp3',
                'file_size': 3407202
            }
        }

CATALOG_BASE = 'catalog'
CHUNK_SIZE = 1024 * 4

#Decrypt song
key_to_files = getpass()

with open("catalog/898a08080d1840793122b7e118b27a95d117ebce_nonce_salt", "rb") as nonce_salt_reader:
    nonce_salt_json = nonce_salt_reader.read()

nonce_salt_json = json.loads(nonce_salt_json.decode('latin'))
nonce_files = base64.b64decode(nonce_salt_json["nonce"])
salt = base64.b64decode(nonce_salt_json["salt"])


kdf = PBKDF2HMAC(
    algorithm=hashes.SHA512(),
    length=32,
    salt=salt,
    iterations=100000,
    )
key_to_files = kdf.derive(key_to_files.encode())

print(key_to_files)


class MediaServer(resource.Resource):
    isLeaf = True
    users = {}

    nonce_for_licence = os.urandom(16)
    

    #Certificados do servidor e private key
    with open("Server_certificate.pem", "rb") as key_file:
        server_cert_private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
    with open("Server_certificate.crt", "rb") as cert_file:
        server_cert = cert_file.read()
    with open("Certification_Authority.crt", "rb") as cert_file:
        CA_cert = x509.load_pem_x509_certificate(cert_file.read())
        CA_public_key = CA_cert.public_key()

 
    def encrypt_AES(self, key, info, modo):
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


    def encrypt_ChaCha20(self, key, info):
        nonce = os.urandom(16)

        algorithm = algorithms.ChaCha20(key, nonce)
        cipher = Cipher(algorithm, mode=None)
        encryptor = cipher.encryptor()
        data_encrypted = encryptor.update(info)
        return data_encrypted, nonce

    def decrypt_AES(self, key, iv, data_encrypted, modo, tag=None):
        if modo == "CBC":
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            unpadder = padding.PKCS7(128).unpadder()

            data = decryptor.update(data_encrypted) + decryptor.finalize()
            info = unpadder.update(data) + unpadder.finalize()
            return info

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

    def decrypt_ChaCha20(self, key, nonce, data_encrypted):
        algorithm = algorithms.ChaCha20(key, nonce)
        cipher = Cipher(algorithm, mode=None)
        decryptor = cipher.decryptor()
        info = decryptor.update(data_encrypted)

        return info

    def sign(self, data, digest):

        if digest == "SHA256":
            signature = self.server_cert_private_key.sign(
                data.encode(),
                paddingAsymetric.PSS(
                    mgf=paddingAsymetric.MGF1(hashes.SHA256()),          
                    salt_length=paddingAsymetric.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()           
                )
        elif digest == "SHA512":
            signature = self.server_cert_private_key.sign(
                data.encode(),
                paddingAsymetric.PSS(
                    mgf=paddingAsymetric.MGF1(hashes.SHA512()),          
                    salt_length=paddingAsymetric.PSS.MAX_LENGTH
                    ),
                    hashes.SHA512()           
                )
        else:
            return "ERRO"
        
        return signature

    # Send the list of media files to clients
    def do_list(self, request):

        #auth = request.getHeader('Authorization')
        #if not auth:
        #    request.setResponseCode(401)
        #    return 'Not authorized'


        # Build list
        media_list = []
        for media_id in CATALOG:
            media = CATALOG[media_id]
            media_list.append({
                'id': media_id,
                'name': media['name'],
                'description': media['description'],
                'chunks': math.ceil(media['file_size'] / CHUNK_SIZE),
                'duration': media['duration']
                })


        # Return list to client
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps(media_list, indent=4).encode('latin')


    # Send a media chunk to the client
    def do_download(self, request):
        logger.debug(f'Download: args: {request.args}')


        #receber o uuid do client
        req = request.content.read()
        req = json.loads(req.decode())

        signature = base64.b64decode(req["signature"].encode())
        data_signed = json.loads(req["data"])
        uuid = data_signed["uuid"]

        
        client_cert = self.users[uuid]["client_cert"]
        client_public_key_rsa = client_cert.public_key()

        
        #Verificar a assinatura
        if self.users[uuid]["digest"] == "SHA256":
            client_public_key_rsa.verify(
                signature,
                req["data"].encode(),
                paddingAsymetric.PSS(
                    mgf=paddingAsymetric.MGF1(hashes.SHA256()), 
                    salt_length=paddingAsymetric.PSS.MAX_LENGTH
                ),
                hashes.SHA256()         
            )
        elif self.users[uuid]["digest"] == "SHA512":
            client_public_key_rsa.verify(
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
                  

        if self.users[uuid]["Autenticado"]:
            pass
        else:
            return "Erro, user nao autenticado"


        media_id = request.args.get(b'id', [None])[0]               
        logger.debug(f'Download: id: {media_id}')
        media_id = base64.urlsafe_b64decode(media_id)

        
        chunk_id = request.args.get(b'chunk', [b'0'])[0]          
        chunk_id = base64.urlsafe_b64decode(chunk_id)


        #decript media_id e chunk
        if self.users[uuid]["algorithm"] == "AES256":                                                
            iv = data_signed["iv"].encode()
            iv = base64.b64decode(iv)
            iv2 = data_signed["iv2"].encode()
            iv2 = base64.b64decode(iv2)


            key = self.users[uuid]["shared_key"]

            if self.users[uuid]["mode"] == "CBC":
                media_id = self.decrypt_AES(key, iv, media_id, "CBC")
                chunk_id = self.decrypt_AES(key, iv2, chunk_id, "CBC")
            elif self.users[uuid]["mode"] == "GCM":
                tag1 = data_signed["tag1"].encode()
                tag1 = base64.b64decode(tag1)
                tag2 = data_signed["tag2"].encode()
                tag2 = base64.b64decode(tag2)
                media_id = self.decrypt_AES(key, iv, media_id, "GCM", tag1)
                chunk_id = self.decrypt_AES(key, iv2, chunk_id, "GCM", tag2)

        elif self.users[uuid]["algorithm"] == "ChaCha20":                                                    
            nonce = data_signed["nonce"].encode()
            nonce = base64.b64decode(nonce)
            nonce2 = data_signed["nonce_chunk"].encode()
            nonce2 = base64.b64decode(nonce2)

            key = self.users[uuid]["shared_key"]
            media_id = self.decrypt_ChaCha20(key, nonce, media_id)
            chunk_id = self.decrypt_ChaCha20(key, nonce2, chunk_id)

        else:
            print("Erro1")
            sys.exit(0)
        

        # Check if the media_id is not None as it is required
        if media_id is None:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'invalid media id'}).encode('latin')
        
        # Convert bytes to str
        media_id = media_id.decode('latin')

        # Search media_id in the catalog
        if media_id not in CATALOG:
            request.setResponseCode(404)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'media file not found'}).encode('latin')
        
        # Get the media item
        media_item = CATALOG[media_id]

        valid_chunk = False
        try:
            chunk_id = int(chunk_id.decode('latin'))
            if chunk_id >= 0 and chunk_id  < math.ceil(media_item['file_size'] / CHUNK_SIZE):
                valid_chunk = True
        except:
            logger.warn("Chunk format is invalid")

        if not valid_chunk:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'invalid chunk id'}).encode('latin')

        
        licenca = self.users[uuid]["licenca"]
        cipher_l = Cipher(algorithms.ChaCha20(key_to_files, self.nonce_for_licence), mode=None)
        decryptor_l = cipher_l.decryptor()
        licenca_d = decryptor_l.update(licenca) + decryptor_l.finalize()
        licenca = json.loads(licenca_d.decode())


        if licenca[uuid]["usos"] == 0 :
            print("Client nao tem licenca para ouvir a musica")

            data = {'error': 'Nao tem licenca para ouvir a musica'}
            data = json.dumps(data)
            signature = self.sign(data, self.users[uuid]["digest"])

            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({"data": data, "signature": base64.b64encode(signature).decode('latin')}).encode('latin')
        else:
            licenca[uuid]["usos"] -= 1
            licenca = json.dumps(licenca).encode()
            cipher_l = Cipher(algorithms.ChaCha20(key_to_files, self.nonce_for_licence), mode=None)
            encryptor_l = cipher_l.encryptor()
            licenca_e = encryptor_l.update(licenca) + encryptor_l.finalize()
            self.users[uuid]["licenca"] = licenca_e
              

        logger.debug(f'Download: chunk: {chunk_id}')

        offset = chunk_id * CHUNK_SIZE

        # Open file, seek to correct position and return the chunk
        with open(os.path.join(CATALOG_BASE, media_item['file_name']), 'rb') as f:

            f.seek(offset)
            data = f.read(CHUNK_SIZE)       

            decryptor_filess = self.users[uuid]["decriptor"]
            data = decryptor_filess.update(data)

            info = json.dumps(
                    {
                        'media_id': media_id, 
                        'chunk': chunk_id, 
                        'data': binascii.b2a_base64(data).decode('latin').strip()
                    },indent=4
                ).encode('latin')


            if self.users[uuid]["algorithm"] == "ChaCha20":        
                salt = os.urandom(16)

                #Encript then MAC
                if self.users[uuid]["digest"] == "SHA256":
                    #Derivar chave 
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=salt,
                        iterations=100000,
                    )
                    key = kdf.derive(self.users[uuid]["shared_key"])
                
                    data_encrypted, nonce = self.encrypt_ChaCha20(key, info)

                    h = hmac.HMAC(key, hashes.SHA256())
                    h.update(data_encrypted)
                    MAC = h.finalize()

                elif self.users[uuid]["digest"] == "SHA512":
                    #Derivar chave 
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA512(),
                        length=32,
                        salt=salt,
                        iterations=100000,
                    )
                    key = kdf.derive(self.users[uuid]["shared_key"])
                
                    data_encrypted, nonce = self.encrypt_ChaCha20(key, info)
                    h = hmac.HMAC(key, hashes.SHA512())
                    h.update(data_encrypted)
                    MAC = h.finalize()

                else:
                    print("Erro")
                    sys.exit(0)

                nonce = base64.b64encode(nonce).decode('latin')
                data_encrypted = base64.b64encode(data_encrypted).decode('latin')
                MAC = base64.b64encode(MAC).decode('latin') 
                salt = base64.b64encode(salt).decode('latin')                                                                                      
                

                data = { "data": data_encrypted, "nonce": nonce, "MAC": MAC, "salt": salt}
                data = json.dumps(data)

                signature = self.sign(data, self.users[uuid]["digest"])
                payload = {"data": data, "signature": base64.b64encode(signature).decode('latin') }


                request.setResponseCode(200)
                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                return json.dumps(payload).encode('latin')

            elif self.users[uuid]["algorithm"] == "AES256":         
                salt = os.urandom(16)

                if self.users[uuid]["digest"] == "SHA256":
                    #Derivar chave 
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=salt,
                        iterations=100000,
                    )
                    key = kdf.derive(self.users[uuid]["shared_key"])

                elif self.users[uuid]["digest"] == "SHA512":
                    #Derivar chave 
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA512(),
                        length=32,
                        salt=salt,
                        iterations=100000,
                    )
                    key = kdf.derive(self.users[uuid]["shared_key"])

                else:
                    print("Erro3")
                    sys.exit(0)

                if self.users[uuid]["mode"] == "CBC":
                    data_encrypted, iv = self.encrypt_AES(key, info, "CBC")
                    tag = None
                elif self.users[uuid]["mode"] == "GCM":
                    data_encrypted, iv, tag = self.encrypt_AES(key, info, "GCM")

                #Encript then MAC
                c = cmac.CMAC(algorithms.AES(key))
                c.update(data_encrypted)
                MAC = c.finalize()

                iv = base64.b64encode(iv).decode('latin')
                data_encrypted = base64.b64encode(data_encrypted).decode('latin')
                MAC = base64.b64encode(MAC).decode('latin')

                salt = base64.b64encode(salt).decode('latin')

                if tag:
                    tag = base64.b64encode(tag).decode('latin')
                    data = { "data": data_encrypted, "iv": iv, "MAC": MAC, "salt": salt, "tag": tag}
                else:
                    data = { "data": data_encrypted, "iv": iv, "MAC": MAC, "salt": salt}


                data = json.dumps(data)
                signature = self.sign( data, self.users[uuid]["digest"])
                payload = { "data": data, "signature": base64.b64encode(signature).decode('latin')} 

                request.setResponseCode(200)
                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                return json.dumps(payload).encode('latin')            

            else:
                print("erro")


        # File was not open?
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps({'error': 'unknown'}, indent=4).encode('latin')


    def do_get_protocols(self, request):
        req = request.content.read()
        req = json.loads(req.decode())

        signature = base64.b64decode(req["signature"].encode())
        data_signed = json.loads(req["data"])

        client_uuid = data_signed["uuid"]
        CLIENT_CIPHERSUITS = data_signed["client_ciphersuits"]
        cc_cert_pem = data_signed["cc_cert"].encode()

        #Verificar a assinatura do CC
        cc_cert = x509.load_pem_x509_certificate(cc_cert_pem)
        cc_cert.public_key().verify(
            signature,
            data=json.dumps(data_signed).encode(),
            padding=paddingAsymetric.PKCS1v15(),
            algorithm=hashes.SHA1()
        )   

        SERVER_CIPHERSUITS = ["AES256_CBC_SHA256", "AES256_CBC_SHA512", "AES256_GCM_SHA256", "AES256_GCM_SHA512", "ChaCha20_None_SHA256", "ChaCha20_None_SHA512"]

        ciphersuit = random.choice(CLIENT_CIPHERSUITS)

        #Procura uma ciphersuit suportada pelo client e pelo servidor
        while len(CLIENT_CIPHERSUITS) > 0:
            if ciphersuit in SERVER_CIPHERSUITS:
                logger.debug(f'Ciphersuit defined: {ciphersuit}')
                break
            else:
                CLIENT_CIPHERSUITS.remove(ciphersuit)
                ciphersuit = random.choice(CLIENT_CIPHERSUITS)
                if len(CLIENT_CIPHERSUITS) == 0:
                    return b'Server doesnt support clients ciphersuit'


        algorithms_modes_digests = ciphersuit.split("_")
        algorithm = algorithms_modes_digests[0]
        mode = algorithms_modes_digests[1]
        digest_c = algorithms_modes_digests[2]


        files_cipher = Cipher(algorithms.ChaCha20(key_to_files, nonce_files), mode=None)
        decryptor_files = files_cipher.decryptor()


        #verificar se o user ja estava inscrito
        if client_uuid in self.users.keys():
            self.users[client_uuid]["algorithm"] = algorithm
            self.users[client_uuid]["mode"] = mode
            self.users[client_uuid]["digest"] = digest_c
            self.users[client_uuid]["decriptor"] = decryptor_files
        else:                                                  
            licenca = json.dumps({ client_uuid: { "usos": 100 } }).encode()
            cipher = Cipher(algorithms.ChaCha20(key_to_files, self.nonce_for_licence), mode=None)
            encryptor = cipher.encryptor()
            licenca_e = encryptor.update(licenca) + encryptor.finalize()
            self.users[client_uuid] = { "algorithm": algorithm, "mode": mode, "digest": digest_c, "licenca": licenca_e, "cc_cert": cc_cert, "Autenticado": True, "decriptor": decryptor_files }


        data = { "ciphersuit": ciphersuit, "server_cert": self.server_cert.decode('latin') }
        data = json.dumps(data)

        if self.users[client_uuid]["digest"] == "SHA256":
            signature = self.server_cert_private_key.sign(
                    data.encode(),
                    paddingAsymetric.PSS(
                        mgf=paddingAsymetric.MGF1(hashes.SHA256()),          
                        salt_length=paddingAsymetric.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()           
                    )
        elif self.users[client_uuid]["digest"] == "SHA512":
             signature = self.server_cert_private_key.sign(
                    data.encode(),
                    paddingAsymetric.PSS(
                        mgf=paddingAsymetric.MGF1(hashes.SHA512()),          
                        salt_length=paddingAsymetric.PSS.MAX_LENGTH
                        ),
                        hashes.SHA512()           
                    )
        else:
            print("Erro")


        payload = { "data": data, "signature": base64.b64encode(signature).decode('latin') }
        request.setResponseCode(200)
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps(payload).encode('latin')


    def do_get_keys(self, request):

        req = request.content.read()
        req = json.loads(req.decode())

        signature = base64.b64decode(req["signature"].encode())
        data_signed = json.loads(req["data"])
        client_uuid = data_signed["uuid_c"]

        client_cert = x509.load_pem_x509_certificate(data_signed["client_cert"].encode())
        client_public_key_rsa = client_cert.public_key()


        #Verificar que o certificado recebido esta assinado pela CA                                                             
        self.CA_public_key.verify(
            client_cert.signature,
            client_cert.tbs_certificate_bytes,
            paddingAsymetric.PKCS1v15(),
            client_cert.signature_hash_algorithm,
        )

        #Verificar a assinatura
        if self.users[client_uuid]["digest"] == "SHA256":
            client_public_key_rsa.verify(
                signature,
                req["data"].encode(),
                paddingAsymetric.PSS(
                    mgf=paddingAsymetric.MGF1(hashes.SHA256()), 
                    salt_length=paddingAsymetric.PSS.MAX_LENGTH
                ),
                hashes.SHA256()         
            )
        elif self.users[client_uuid]["digest"] == "SHA512":
            client_public_key_rsa.verify(
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

        self.users[client_uuid]["client_cert"] = client_cert


        #TODO:
        p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        g = 2
        params_numbers = dh.DHParameterNumbers(p,g)
        parameters = params_numbers.parameters(default_backend())
        #parameters = dh.generate_parameters(generator=2, key_size=2048)                                                   
        parameters_pem = parameters.parameter_bytes(Encoding.PEM, ParameterFormat.PKCS3)

        # Generate a private key DH
        self.server_private_key = parameters.generate_private_key()

        # Generate a public DH
        server_public_key_pem = self.server_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        data = { "parameters": parameters_pem.decode('latin'), "server_pub_key": server_public_key_pem.decode('latin') }
        data = json.dumps(data)

        if self.users[client_uuid]["digest"] == "SHA256":
            signature = self.server_cert_private_key.sign(
                data.encode(),
                paddingAsymetric.PSS(
                    mgf=paddingAsymetric.MGF1(hashes.SHA256()),          
                    salt_length=paddingAsymetric.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()           
                )   
                
        elif self.users[client_uuid]["digest"] == "SHA512":
            signature = self.server_cert_private_key.sign(
                data.encode(),
                paddingAsymetric.PSS(
                    mgf=paddingAsymetric.MGF1(hashes.SHA512()),          
                    salt_length=paddingAsymetric.PSS.MAX_LENGTH
                    ),
                    hashes.SHA512()   
                )
        else:
            print("Erro")                                        
            sys.exit(0)

        payload = {"signature": base64.b64encode(signature).decode('latin'), "message": data }
        
        request.setResponseCode(200)
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps(payload).encode('latin')


    # Handle a GET request
    def render_GET(self, request):
        logger.debug(f'Received request for {request.uri}')

        try:
            if request.path == b'/api/protocols':
                return self.do_get_protocols(request)
            elif request.uri == b'/api/key':
                return self.do_get_keys(request)
            #...
            #elif request.uri == 'api/auth':

            elif request.path == b'/api/list':
                return self.do_list(request)

            elif request.path == b'/api/download':
                return self.do_download(request)
            else:
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return b'Methods: /api/protocols /api/list /api/download'

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''




    
    def shared_key(self, request):

        req = request.content.read()
        req = json.loads(req.decode())

        signature = base64.b64decode(req["signature"].encode())
        data_signed = json.loads(req["data"])

        client_pub_key_pem = data_signed["client_pub_key"].encode()
        client_uuid = data_signed["uuid"]

        client_cert = self.users[client_uuid]["client_cert"]
        client_public_key_rsa = client_cert.public_key()

        #verificar assinatura
        if self.users[client_uuid]["digest"] == "SHA256":
            client_public_key_rsa.verify(
                signature,
                req["data"].encode(),
                paddingAsymetric.PSS(
                    mgf=paddingAsymetric.MGF1(hashes.SHA256()), 
                    salt_length=paddingAsymetric.PSS.MAX_LENGTH
                ),
                hashes.SHA256()         
            )
        elif self.users[client_uuid]["digest"] == "SHA512":
            client_public_key_rsa.verify(
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

        
        client_pub_key = load_pem_public_key(client_pub_key_pem)                
        shared_key = self.server_private_key.exchange(client_pub_key)        

        if self.users[client_uuid]["digest"] == "SHA256":
            shared_key_derived = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
            ).derive(shared_key)
        elif self.users[client_uuid]["digest"] == "SHA512":
            shared_key_derived = HKDF(
                algorithm=hashes.SHA512(),
                length=32,
                salt=None,
                info=b'handshake data',
            ).derive(shared_key)
        else:
            sys.exit(0)
        
        self.users[client_uuid]["shared_key"] = shared_key_derived

        return 'OK'
    
    # Handle a POST request
    def render_POST(self, request):
        try:
            if request.path == b'/api/protocols':
                return self.negociate_protocols(request)           
            elif request.path == b'/api/shared_key':
                return self.shared_key(request)
            else:
                return 'nothing'
        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''
        #request.setResponseCode(501)


print("Server started")
print("URL is: http://IP:8080")

s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()