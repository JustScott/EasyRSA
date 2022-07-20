# <p align='center'>RapidRSA</p>
<p align='center'>Simpler to use implementation of the pycryptodome RSA algorithm</p>

<br>
<br>

# Example Use
```python
message = "Example Text"

rsa = rsa()

e = rsa.encrypt(message)
d = rsa.decrypt(e)
```
<h4>Easily Create and Verify Signatures</h4>

```python
message = "Example Text"

rsa = rsa()

e = rsa.encrypt(message)

signature, digest = rsa.create_signature(message)

if rsa.verify_signature(signature, digest):
    d = rsa.decrypt(e)
```
<br>

<h2>Required Dependences From PyPi</h2>

<h4>pycryptodome >= 3.15.0</h4>

- <a href="https://github.com/Legrandin/pycryptodome">pycryptodome on GitHub</a>

- <a href="https://pypi.org/project/pycryptodome/">pycryptodome on PyPi</a>


<br>

# Documentation
```python
'''
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
```
