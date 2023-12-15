from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from src.utils.common_utils import  read_file_content, create_zip_buffer
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.primitives import serialization
from ecies import encrypt, decrypt
import os
from ecies.utils import generate_eth_key, generate_key

def aes_encrypt(plain_file, secret_pass):
    plain_file_data = read_file_content(plain_file)

    # ECC keys.
    _key = generate_eth_key()
    private_key = _key.to_hex()
    public_key = _key.public_key.to_hex()
    
    # symmetric key
    key = os.urandom(16)
    symmetric_key = encrypt(public_key, key)
    iv = os.urandom(16)
    
    # encrypt the message
    cipher = cipher(algorithms.aes(symmetric_key), modes.ctr(iv))
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(plain_file_data.getvalue()) + encryptor.finalize()

    files_dict = {
        'cipher.encr': cipher_text,
        'sym_key.pem': symmetric_key,
        'key.pem': _key
    }
    
    return create_zip_buffer(files_dict) 
    
    return cipher_text


def aes_decrypt(cipher_file, key_file, symmetric_key_file, secret_pass): 
    cipher_file_data = read_file_content(cipher_file)
    eth_key = read_file_content(key_file)
    private_key = eth_key.getvalue().to_hex()
    symmetric_key = decrypt(private_key, symmetric_key_file)
    cipher = Cipher(algorithms.AES256(symmetric_key), modes.CTR(os.urandom(16)))
    decryptor = cipher.decryptor()
    plain_text = decryptor.update(cipher_file_data.getvalue()) + decryptor.finalize()
    return plain_text


