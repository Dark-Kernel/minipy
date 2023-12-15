from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from src.utils.common_utils import read_file_content, create_zip_buffer


def rsa_encrypt(plain_file, secret_pass, existing_key):
    try:
        if plain_file and plain_file.filename:
            file_data = read_file_content(plain_file)

            if existing_key and existing_key.filename:
                existing_key_data = read_file_content(existing_key)
                private_key = serialization.load_pem_private_key(
                    existing_key_data.getvalue(),
                    password=secret_pass.encode('utf-8'), #password=None,
                    backend=default_backend()
                ) 
                public_key = private_key.public_key()

            else:
                # key generation
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )

                # signature
                signature = private_key.sign(
                    file_data.getvalue(),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                        ),
                    hashes.SHA256()
                )

                # verification
                public_key = private_key.public_key()
                public_key.verify(
                    signature,
                    file_data.getvalue(),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )

                # Encryption
            cipher_text = public_key.encrypt(
                file_data.getvalue(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            if existing_key and existing_key.filename: 
                return cipher_text;
            
            # send files
            files_dict = {
                'cipher.encr': cipher_text,
                'key.pem': private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(password=secret_pass.encode('utf-8'))
                    #encryption_algorithm=serialization.NoEncryption()
                )
            }

            return  create_zip_buffer(files_dict)
        else:
            return 'Invalid file'

    except Exception as e:
        print(e)
        print(type(e))



def rsa_decrypt(cipher_file, private_key_file, secret_pass):
    try:    
        if cipher_file and cipher_file.filename and private_key_file and private_key_file.filename:

            cipher_data = read_file_content(cipher_file)
            private_key_data = read_file_content(private_key_file)

            private_key = serialization.load_pem_private_key(
                private_key_data.getvalue(),
                password=secret_pass.encode('utf-8'), #password=None,
                backend=default_backend()
            )

            # Decryption
            decrypted_text = private_key.decrypt(
                cipher_data.getvalue(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            return decrypted_text
        else:
            return "invalid file"       
    
    except Exception as e:
        print(e,'\n', type(e))









