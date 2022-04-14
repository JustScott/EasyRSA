'''
A simplified implementation of the RSA algorithm, using the pycryptodome library.


Classes:
    rsa(key_size=2048, public_key=None, private_key=None)
        Can be fully functional and secure without passing any arguments

Methods:
    keygen(self, key_size: int) -> bytes and bytes
        Generates Keys for Encryption/Decryption. The 'key_size' will determine the security
        and speed of your data (bigger is more secure, but slower)
    
    encrypt(self, data: str or bytes, public_key=None) -> bytes
        Only requires a public key if you don't want to use the class generated key

    decrypt(self, encrypted_text: bytes, private_key=None) -> str or bytes
        Only requires a private key if you don't want to use the class generated key

    create_signature(self, data: str, private_key=None) -> bytes and object
        Creates a signature for later verifcation that the data hasn't been tampered
        with during transport

    verify_signature(self, signature: bytes, digest: object, public_key=None) -> bool
        Verifies the signature of the data, ensuring the data hasn't been tampered with

    generate_password(self, length=64) -> str
        Generates a random password to share with the client/server for symmetric cryptography        
    

'''


from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from random import choice
import string

class rsa:
    '''
    Simpler implementation of the pycryptodome RSA algorithm, meant to make it easier to utilize this powerful
    form of asymmetric encryption/decryption
    '''
    def __init__(self, key_size=2048, public_key=None, private_key=None):
        '''
        The __init__ method is being used to autonomously create the public and private keys,
        but leaves the option to supply your own values for the key size and keys

        :method:: __init__(self, key_size=2048, public_key=None, private_key=None)

        Args:
            key_size (int, *optional):
                The size of the key will determine the speed and security of encryption/decrypting 
                the data, a key of size of 2048 is widely accepted as the standard for security and speed
            
            public_key (bytes, *optional):
                Used to encrypt the data and verify signatures


            private_key (bytes, *optional):
                Used to decrypt the data and create signatures
        '''
        self.key_size = key_size

        #Use the keys the user supplied
        if public_key or private_key:
            self.public_key = public_key
            self.private_key = private_key
        #If the user didn't supply keys, generate new ones
        else:
            self.public_key, self.private_key = self.keygen(key_size)


    def keygen(self, key_size: int) -> bytes and bytes:
        '''
        Generates Keys for Encryption/Decryption. The 'key_size' will determine the security
        and speed of your data (bigger is better, but slower)

        :method:: keygen(self, key_size: int) -> bytes and bytes

        Args:
            key_size (int):
                Generally a key size of 2048 is considered safe, anything below that is not recommended for important applications.

        Returns:
            bytes: The Public Key, used for encrypting data

            bytes: The Private Key, used for decrypting data 
        '''
        #Generates a private key object based on the supplied key size
        key = RSA.generate(key_size)

        #Extracts the private key from the key object above
        private_key = key.export_key('PEM')
        #Uses the private key to generate the public key
        public_key = key.publickey().exportKey('PEM')

        return public_key,private_key

    def encrypt(self, data: str or bytes, public_key=None) -> bytes:
        '''
        Only requires a public key if you don't want to use the class generated key

        :method:: encrypt(self, data: str or bytes, public_key=None) -> bytes

        Args:
            public_key (bytes): The key used to encrypt your data, It is safe to 
                share your Public Key with others

            message (str or bytes): The message you want encrypted

        Returns:
            bytes: The encrypted version of your message, can only be decrypted
                by the Private Key of the pair
        '''
        #Allows the user to supply their own public key
        if public_key:
            self.public_key = public_key

        #Converts the data into an encryptable format 
        if type(data) == str:
            data = data.encode()

        #Converts the key to a usable formate
        rsa_public_key = RSA.importKey(self.public_key)
        rsa_public_key = PKCS1_OAEP.new(rsa_public_key)

        encrypted_text = rsa_public_key.encrypt(data)

        return encrypted_text

    def decrypt(self, encrypted_text: bytes, private_key=None) -> str or bytes:
        '''
        Only requires a private key if you don't want to use the class generated key

        :method:: decrypt(self, encrypted_text: bytes, private_key=None) -> str or bytes

        Args:
            private_key (bytes): The key used to decrypt your data, It is NOT 
                safe to share your Private Key with others

            encrypted_text (bytes): The encrypted verison of the message

        Returns:
            str or bytes: The original message
        '''
        #Allows the user to supply their own private key
        if private_key:
            self.private_key = private_key

        #Converts the key to a usable format
        rsa_private_key = RSA.importKey(self.private_key)
        rsa_private_key = PKCS1_OAEP.new(rsa_private_key)

        decrypted_text = (rsa_private_key.decrypt(encrypted_text)).decode()

        return decrypted_text

    def create_signature(self, data: str, private_key=None) -> bytes and object:
        '''
        Creates a signature for later verifcation that the data hasn't been tampered
        with during transportation
        
        :method:: create_signature(self, data: str, private_key=None) -> bytes and object

        Args:
            data (str):
                The unencrypted data you want signed

            private_key (bytes, *optional):
                The private_key is used to sign the data, to which the signature
                is confirmed by the public key later on

        Returns:
            bytes: The signature is the output of encrypting the digest with the private key

            object: The digest is the hash of the data you want to send 
    
        '''
        #Allows the user to supply their own private key
        if private_key:
            self.private_key = private_key

        #Converts the key to a usable format
        rsa_private_key = RSA.importKey(self.private_key)

        #Hash of the data
        digest = SHA256.new(data.encode())
    
        #The digest encrypted by the private key
        signature = pkcs1_15.new(rsa_private_key).sign(digest)

        return signature, digest


    def verify_signature(self, signature: bytes, digest: object, public_key=None) -> bool:
        '''
        Verifies the signature of the data, ensuring the data hasn't been tampered with

        :method:: verify_signature(self, signature: bytes, digest: object, public_key=None) -> bool

        Args:
            signature (bytes):
                When the signature is decrypted by the public key, and it matches the digest, it
                proves that the message was created by the private key holder, and that it wasn't
                tampered with

            digest (object):
                The hash of the origional data

            public_key (bytes, *optional)
                The public key for verifying that the signature was created by the private key
                its linked to, and that the data isn't tampered with

        Returns:
            bool: True if the signature is correct
        '''
        #Allows the user to supply their own public key
        if public_key:
            self.public_key = public_key

        #Converts the key to a usable format
        rsa_public_key = RSA.importKey(self.public_key)
        
        #returns True if the digest and signature can be verified
        try:
            pkcs1_15.new(rsa_public_key).verify(digest, signature)
            return True
        except ValueError:
            return False

    def generate_password(self, length=64) -> str:
        '''
        Generates a random password to share with the client/server for symmetric cryptography
        
        :method:: generate_password(self, length=64) -> str

        Args:
            length (int, *optional):
                The length of the generated password

        Returns:
            str:
                The randomly generated password
        
        '''
        #Returns every printable ascii character, exluding whitespace characters (other than space)
        characters = string.printable.replace(string.whitespace, " ")

        #Used random.choice() to choose random characters from the 'characters' variable, then joins them into a string
        password = "".join([choice(characters) for i in range(length)])

        return password


if __name__=="__main__":
    #Example use of the rsa class 
    if False:
        message = "Example Text"

        rsa = rsa()

        e = rsa.encrypt(message)

        d = rsa.decrypt(e)

    #Example of using signatures to ensure data integrity
    if False:
        message = "Example Text"

        rsa = rsa()

        e = rsa.encrypt(message)

        signature, digest = rsa.create_signature(message)

        if rsa.verify_signature(signature, digest):
            d = rsa.decrypt(e)
