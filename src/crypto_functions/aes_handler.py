from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from src.utils.common_utils import read_file_content, create_zip_buffer
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from ecies.utils import generate_key
from ecies import encrypt, decrypt
import os

def aes_encrypt(plain_file, secret_pass):
    plain_file_data = read_file_content(plain_file)

    # ECC keys generation.
    _key = generate_key() 
    public_key = _key.public_key.format(True)

    # Initialization Vector
    iv = os.urandom(16)
    
    # Setting up HKDF (HMAC)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=None
    )

    # Deriving symmetric key from secret_pass using HKDF.
    aes_key = hkdf.derive(secret_pass.encode('UTF-8'))

    # Encrypt plain_data using AES256
    cipher = Cipher(algorithms.AES256(aes_key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(plain_file_data.getvalue()) + encryptor.finalize()
    
    # Merging cipher text and iv
    cipher_text = iv + cipher_text

    # Encrypting the symmetric key usig ECC public key.
    encrypted_aes = encrypt(public_key, aes_key)

    # Zipping the files.
    files_dict = {
        'cipher.encr': cipher_text,
        'sym_key.pem': encrypted_aes,
        'key.pem': _key.to_hex(),
    }
    
    # Returning the zip file
    return create_zip_buffer(files_dict) 
    


def aes_decrypt(cipher_file, key_file, symmetric_key_file): 
    # Setting up variable with correct contents.
    cipher_file_data = read_file_content(cipher_file)
    eth_key = read_file_content(key_file)
    symmetric_key_data = read_file_content(symmetric_key_file)

    private_key = eth_key.getvalue().decode()
    
    # Seperate the iv & cipher text.
    iv = cipher_file_data.getvalue()[:16]
    cipher_file_data = cipher_file_data.getvalue()[16:]
    
    # Decrypting the symmetric key using ECC private_key.
    symmetric_key = decrypt(bytes.fromhex(private_key), symmetric_key_data.getvalue())
    
    # Decrypting the cipher text.
    cipher = Cipher(algorithms.AES256(symmetric_key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    plain_text = decryptor.update(cipher_file_data) + decryptor.finalize()

    ## Incase of hex representation
    # hex_representation = ''.join(format(byte, '02x') for byte in plain_text)
    # hexen = bytes.fromhex(hex_representation)
    # binary_string = ' '.join(format(byte, '08b') for byte in hexen)
    # print(hex_representation)
    
    return plain_text


