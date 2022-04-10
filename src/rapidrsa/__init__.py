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


from rapidrsa.rapidrsa import rsa
