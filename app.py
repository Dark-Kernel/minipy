from flask import Flask, request, send_file, make_response
import os, io, zipfile
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)


@app.route('/', methods=['GET'])
def start():
    return "This is root"


@app.route('/upload', methods=['GET', 'POST'])
def receive():
    secret_pass = request.form.get("pass")
    plain_file = request.files.get("file")
    if plain_file and plain_file.filename:
        file_data = io.BytesIO()
        plain_file.seek(0)
        file_data.write(plain_file.read())
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
        
        # send files
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'a', zipfile.ZIP_DEFLATED, False) as zip_file:
            zip_file.writestr('cipher.encr', cipher_text)
            zip_file.writestr('key.pem', private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password=secret_pass.encode('utf-8'))
                #encryption_algorithm=serialization.NoEncryption()
            ))
            
        zip_buffer.seek(0)
        
        return send_file(zip_buffer, mimetype='application/zip', as_attachment=True, download_name='encrypted.zip')          
    
    else:
        return 'invalid file'
    

@app.route('/decr', methods=['GET', 'POST'])
def send_decrypt():
    secret_pass = request.form.get("pass")
    cipher_file = request.files.get("cipher")
    private_key_file = request.files.get("privkey")
    if cipher_file and cipher_file.filename and private_key_file and private_key_file.filename:
        cipher_data = io.BytesIO()
        cipher_file.seek(0)
        cipher_data.write(cipher_file.read()) 

        private_key_data = io.BytesIO()
        private_key_file.seek(0)
        private_key_data.write(private_key_file.read())

        private_key = serialization.load_pem_private_key(
            private_key_data.getvalue(),
            password=secret_pass.encode('utf-8'),
            #password=None,
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

        response = send_file(io.BytesIO(decrypted_text), mimetype='text/plain', as_attachment=True, download_name='decrypted.txt')
        response.headers.add('Content-Disposition', 'attachment')

        return response
    else:
        return "invalid file"       



if __name__ == '__main__':
    app.run(debug=True, threaded=True)
    