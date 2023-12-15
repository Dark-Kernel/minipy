from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from src.utils.common_utils import read_file_content, create_zip_buffer
import base64, os


def fernet_encrypt(plain_file, secret_pass, existing_key):
    if plain_file and plain_file.filename:
        plain_data = read_file_content(plain_file)
        if existing_key and existing_key.filename:
            existing_key_data = read_file_content(existing_key)
            f = Fernet(existing_key_data.getvalue())
            cipher_data = f.encrypt(plain_data.getvalue())
            return cipher_data
        
        if secret_pass != None:
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=480000
            )
            key = base64.urlsafe_b64encode(kdf.derive(secret_pass.encode('utf-8'))) # key = Fernet.generate_key()
        else:
            key = Fernet.generate_key()
 
        f = Fernet(key)
        cipher_data = f.encrypt(plain_data.getvalue())
         
        files_dict = {
            'cipher.encr': cipher_data,
            'key.pem': key
        }

        return create_zip_buffer(files_dict)
    else:
        return "invalid file"


    
def fernet_decrypt(cipher_file, key_file, secret_pass=None):
    if cipher_file and cipher_file.filename:
        cipher_data = read_file_content(cipher_file)
        key_data = read_file_content(key_file)
        f = Fernet(key_data.getvalue())
        plain_data = f.decrypt(cipher_data.getvalue())
        return plain_data
    else:
        return "invalid file"
        
        