import os
from cryptography.hazmat.primitives import hmac,padding,hashes
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
import base64
import socket
# Assignment 3 main file
# Feel free to modify, and/or to add other modules/classes in this or other files

#Reference:
## Technical Dcoumentation
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/dh/
#https://cryptography.io/en/latest/hazmat/primitives/asymmetric/dh/
#https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/
#https://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#DH2Ex
#https://pythontic.com/modules/socket/recv
# https://www.ietf.org/rfc/rfc3526.txt
## Videos
# https://youtu.be/NmM9HA2MQGI
# https://youtu.be/Yjrfm_oRO0w
# https://youtu.be/KXq065YrpiU


# Key Derivation VIA HKDF
class Security:
    mcpiPublicKey=None
    mcpiPrivateKey=None
    serverPublicKey=None
    encryption_key=None
    authentication_key=None
    sharedSecret=None
    
    def __init__(self):
        self.mcpiPublicKey=None
        self.mcpiPrivateKey=None
        self.serverPublicKey=None
        self.encryption_key=None
        self.authentication_key=None
        self.intialize_key_exchange()
        self.sharedSecret=None

    def getEncryptionKey(self):
        encryption_key_length= 32
        encryption_salt=b'encrypt_salt'
        encryption_info=b'encryption_info'
        derivation_function=HKDF(
            algorithm=hashes.SHA256(),
            length=encryption_key_length,
            salt=encryption_salt,
            info=encryption_info,
            backend=default_backend())
        derived_encryption_key=derivation_function.derive(self.sharedSecret)
        self.encryption_key=derived_encryption_key
        
    def getAuthenticationKey(self):
        authentication_key_length=32
        authentication_salt=b'auth_salt'
        authentication_info=b'authentication_info'
        derivation_function=HKDF(
            algorithm=hashes.SHA256(),
            length=authentication_key_length,
            salt=authentication_salt,
            info=authentication_info,
            backend=default_backend())
        derived_authentication_key=derivation_function.derive(self.sharedSecret)
        self.authentication_key=derived_authentication_key
        
    def aes_256_cbc_encrypt(self,content):   
        # Pad the data
        BLOCK_SIZE=256
        pkcs7_padding=padding.PKCS7(BLOCK_SIZE).padder()
        
        padded_content=pkcs7_padding.update(content) + pkcs7_padding.finalize()
        
        
        # Generate Intializaation Vector Required for CBC Mode of Operation
        iv=os.urandom(128//8)
        
        # AES-CBC cipher
        aes_256_cipher= Cipher(AES(self.encryption_key),CBC(iv))
        
        content_encrypted=aes_256_cipher.encryptor().update(padded_content)
        
        return iv + content_encrypted

    def create_hmac_sha_256(self,content_encrypted):
        # Set up Hash Function SHA-256
        hash_function=hashes.SHA256()
        # Intialize HMAC function with key and SHA-256 hash function
        hmac_object=hmac.HMAC(self.authentication_key,hash_function)
        # Create the HMAC tag on the encrypted_content
        hmac_object.update(content_encrypted)
        
        hmac_tag=hmac_object.finalize()
        return hmac_tag
        
        
        
        

    def verify_hmac_256(self,received_mac_tag,received_cipher_text):
        # Set up Hash Function SHA-256
        hash_function=hashes.SHA256()
        # Intialize HMAC function with key and SHA-256 hash function
        hmac_object=hmac.HMAC(self.authentication_key,hash_function)
    #Create the HMAC tag on received Content
        hmac_object.update(received_cipher_text)
        # Verify the generated tag against the received hmac tag 
        # Raises Exception if not equivalent 
        hmac_object.verify(received_mac_tag)
        

    def aes_256_cbc_decrypt(self,received_content):
        
        # Seperate the IV and the cipher text
        iv = received_content[:16]
        encrypted_content=received_content[16:]
        
        # Decrypt the encrypted content into padded plaintext
        aes_256_cipher=Cipher(AES(self.encryption_key),CBC(iv))
        padded_content= aes_256_cipher.decryptor().update(encrypted_content)
        
        # Removal of Padding 
        
        pkcs7_unpadding=padding.PKCS7(256).unpadder()
        
        unencrypted_content= pkcs7_unpadding.update(padded_content) + pkcs7_unpadding.finalize()
        
        return unencrypted_content


 


# Getters

    def getMCPIPublicKey(self):
        return self.mcpiPublicKey



    def intialize_key_exchange(self):
        # RFC-3526 Prime Number and Generator
        P=0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        G=2
        
        # Intialize DH Parameters then generator Private Key
        parameter_num=dh.DHParameterNumbers(P,G)
        parameters=parameter_num.parameters(default_backend())
        self.mcpiPrivateKey=parameters.generate_private_key()
        

        self.mcpiPublicKey=self.mcpiPrivateKey.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        
        return 
    


    def received_public_key(self,server_public_key_bytes):

    
        
        print("PUBLIC KEY BYTES SERVER: ", server_public_key_bytes)
        # Deserialize the server public key
        self.serverPublicKey= serialization.load_der_public_key(
            server_public_key_bytes,
            backend=default_backend()
        )
       

    def generateSharedSecret(self):
        client_shared_key=self.mcpiPrivateKey.exchange(self.serverPublicKey)
        self.sharedSecret=client_shared_key



if __name__=="__main__":
    
    #  Establish Connection
    server_address = 'localhost'
    server_port = 4711
    mcpi_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mcpi_socket.connect((server_address, server_port))

    
    
    
    # 2 KEYS for AES-256-CBC and HMAC-SHA-256
    # Temporary until DH implementation
    
    sharedSecret=mcpi_sec_dh.key_exchange(mcpi_socket)
    # print("sharedSecret:",sharedSecret.hex())


    # mcpi_socket.close()
    encryption_key= getEncryptionKey(sharedSecret)

    # print("ENCRYPTED KEY:",encryption_key.hex())
    
    authentication_key= getAuthenticationKey(sharedSecret)
     
    # print(authentication_key.hex())

    #Encrypt Then Mac
    message_plain='bruh does this easdasdasdasdasdven work?'
    
    # Convert the text to bytes
    message_bytes=message_plain.encode('utf-8')
   
    # Encryption via AES 256 CBC
    encrypted_content=aes_256_cbc_encrypt(message_bytes,encryption_key)
    # print('ENCRYPTED CONTENT:',encrypted_content.hex())
    print(len(encrypted_content))
    # Create The Mac Tag 
    mac_tag=create_hmac_sha_256(encrypted_content,authentication_key)
    
    encrypted_content_tagged=mac_tag+encrypted_content
    print(encrypted_content_tagged)
    print(len(encrypted_content_tagged))
    # mcpi_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # mcpi_socket.connect((server_address,server_port))

            
    encrypted_content_string=base64.b64encode(encrypted_content_tagged)
    # print(encrypted_content_string)
    mcpi_socket.sendall(encrypted_content_string)


    # print(encrypted_content)
    # print(mac_tag)
    #Transfer to server (For testing purposes)
    received_encrypted_content=encrypted_content
    
    
    received_mac_tag= mac_tag 
    
    # Server verifies MAC --> if valid --> decryption else raise exception
    
    
    # try:
    #     verify_hmac_256(received_mac_tag,received_encrypted_content,authentication_key)
    # except InvalidSignature:
    #      print("INVALID MAC TAG")
    # else:
    #     unencrypted_content=aes_256_cbc_decrypt(received_encrypted_content,encryption_key)
    #     if message_bytes==unencrypted_content:
    #         print("ENCRYPTION - DECRYPTION SUCCESFUL")
         