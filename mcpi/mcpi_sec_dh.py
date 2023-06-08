
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import socket
from codecs import decode 
import base64

#References

## Technical Dcoumentation
#https://cryptography.io/en/latest/hazmat/primitives/asymmetric/dh/
#https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/
#https://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#DH2Ex
#https://pythontic.com/modules/socket/recv
# https://www.ietf.org/rfc/rfc3526.txt
## Videos
# https://youtu.be/NmM9HA2MQGI
# https://youtu.be/Yjrfm_oRO0w
# https://youtu.be/KXq065YrpiU



def intialize_key_exchange():
    # RFC-3526 Prime Number and Generator
    P=0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    G=2
    
    # Intialize DH Parameters then generator Private Key
    parameter_num=dh.DHParameterNumbers(P,G)
    parameters=parameter_num.parameters(default_backend())
    mcpi_private_key=parameters.generate_private_key()

    mcpi_public_key=mcpi_private_key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)

    return base64.b64encode(mcpi_public_key)
   


def received_public_key(server_public_key_bytes):
    server_public_key_bytes=base64.b64decode(server_public_key_bytes)
    # print(server_public_key_bytes)
    
    # Deserialize the server public key
    server_public_key = serialization.load_der_public_key(
        server_public_key_bytes,
        backend=default_backend()
    )


def generateSharedSecret(mcpi_private_key,server_public_key):
    client_shared_key=mcpi_private_key.exchange(server_public_key)
    return client_shared_key


