from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from src.utils.common_utils import  read_file_content, create_zip_buffer
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from ecies import encrypt, decrypt
import os
from ecies.utils import generate_eth_key, generate_key

def aes_encrypt(plain_file, secret_pass):
    plain_file_data = read_file_content(plain_file)


 #   ECC keys.
    _key = generate_eth_key()
    _key2 = generate_key() # -> last cursor
    private_key = _key.to_hex()
    public_key = _key.public_key.to_hex()

    
    # symmetric key
    # key = os.urandom(32)
    # symmetric_key = encrypt(public_key, key)
    # symmetric_key = symmetric_key[:32]
    # resize the symmetric_key variable to 32 bytes size.
    

    iv = os.urandom(16)
    
    # encrypt the message
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=None
    )

    # Derive symmetric key from secret_pass.
    aes_key = hkdf.derive(secret_pass.encode('UTF-8'))
    

    # Encrypt plain_data
    cipher = Cipher(algorithms.AES256(aes_key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(plain_file_data.getvalue()) + encryptor.finalize()
    
    # encrypt the symmetric key.
    encrypted_aes = encrypt(public_key, aes_key)

    files_dict = {
        'cipher.encr': cipher_text,
        'sym_key.pem': encrypted_aes,
        'key.pem': _key.to_hex()
    }
    
    return create_zip_buffer(files_dict) 
    


def aes_decrypt(cipher_file, key_file, symmetric_key_file, secret_pass): 
    cipher_file_data = read_file_content(cipher_file)
    eth_key = read_file_content(key_file)
    private_key = eth_key.getvalue()
    symmetric_key_data = read_file_content(symmetric_key_file)
    symmetric_key = decrypt(private_key, symmetric_key_data.getvalue())
    cipher = Cipher(algorithms.AES256(symmetric_key), modes.CTR(os.urandom(16)))
    decryptor = cipher.decryptor()
    plain_text = decryptor.update(cipher_file_data.getvalue()) + decryptor.finalize()
    return plain_text


