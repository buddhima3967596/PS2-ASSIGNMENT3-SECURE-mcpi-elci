import socket
import select
import sys
from .util import flatten_parameters_to_bytestring
from .mcpi_sec import Security;
import base64

""" @author: Aron Nieminen, Mojang AB"""

class RequestError(Exception):
    pass

class Connection:
    """Connection to a Minecraft Pi game"""
    RequestFailed = "Fail"

    def __init__(self, address, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((address, port))
        # self.secure=Security()
        self.lastSent = ""
        self.perfromExchange()
        
    def perfromExchange(self):
        self.secure=Security()
        
        public_key_encoded=self.secure.getMCPIPublicKey()
        
        # Send Public Key
        print(base64.b64encode(public_key_encoded))
        print(len(base64.b64encode(public_key_encoded)))
        
        
        self.socket.send(base64.b64encode(public_key_encoded)+b'\n')
        
        
        # Received Server Public Key
        serverPublicKeyBytes=self.socket.recv(4000)
        self.secure.received_public_key(base64.b64decode(serverPublicKeyBytes))
        
        # Generate SharedSecre
        self.secure.generateSharedSecret()
        
        # Derive Encryptiona and Authenthication Keys
        
        self.secure.getEncryptionKey()
        
        self.secure.getAuthenticationKey()
        
        print( "\nSHARED SECRET BASE64 " ,  base64.b64encode(self.secure.sharedSecret) )
        print("\nSHARED SECRET BYTES " , self.secure.sharedSecret)
        print("\nENCRYPTION KEY HEX " ,  self.secure.encryption_key.hex())
        print("\nAUTH KEY HEX " ,  self.secure.authentication_key.hex())
        
        
        
        
        
    def drain(self):
        """Drains the socket of incoming data"""
        while True:
            readable, _, _ = select.select([self.socket], [], [], 0.0)
            if not readable:
                break
            data = self.socket.recv(1500)
            e =  "Drained Data: <%s>\n"%data.strip()
            e += "Last Message: <%s>\n"%self.lastSent.strip()
            sys.stderr.write(e)

    
    
    def send(self, f, *data):
        """
        Sends data. Note that a trailing newline '\n' is added here

        The protocol uses CP437 encoding - https://en.wikipedia.org/wiki/Code_page_437
        which is mildly distressing as it can't encode all of Unicode.
        """

        s = b"".join([f, b"(", flatten_parameters_to_bytestring(data), b")"])
        print(s.decode('utf-8'))
        print(s)
        self._send(s)

    def _send(self, s):
        """
        The actual socket interaction from self.send, extracted for easier mocking
        and testing
        """
        self.drain()
        self.lastSent = s
        
        s_encrypted=self.secure.aes_256_cbc_encrypt(s)
        s_tag=self.secure.create_hmac_sha_256(s_encrypted)
        print("ENCRYPTED BYTES LENGTH: " , len(s_encrypted))
        print("ENCRYPTED HEX: " + s_encrypted.hex())
        print("MAC TAG HEX: " + s_tag.hex())
        print("MAC BYTES LENGTH: " , len(s_tag))

        string_final=base64.b64encode(s_tag+s_encrypted)

       
        self.socket.sendall(string_final+b'\n')

    def receive(self):
        """Receives data. Note that the trailing newline '\n' is trimmed"""
        s = self.socket.makefile("r").readline().rstrip("\n")
        if s == Connection.RequestFailed:
            raise RequestError("%s failed"%self.lastSent.strip())
        return s

    def sendReceive(self, *data):
        """Sends and receive data"""
        self.send(*data)
        return self.receive()




   
   