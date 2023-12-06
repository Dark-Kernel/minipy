from flask import Flask, request, send_file
import io
from src.crypto_functions.rsa_handler import rsa_encrypt, rsa_decrypt

app = Flask(__name__)

@app.route('/', methods=['GET'])
def start():
    return "This is root"


@app.route('/encr', methods=['GET', 'POST'])
def receive():
    secret_pass = request.form.get("pass")
    plain_file = request.files.get("file")
    if plain_file and plain_file.filename:
        zip_buffer = rsa_encrypt(plain_file, secret_pass)
        return send_file(zip_buffer, mimetype='application/zip', as_attachment=True, download_name='encrypted.zip')          
    else:
        return 'invalid file'
    

@app.route('/decr', methods=['GET', 'POST'])
def send_decrypt():
    secret_pass = request.form.get("pass")
    cipher_file = request.files.get("cipher")
    private_key_file = request.files.get("privkey")
    if cipher_file and cipher_file.filename and private_key_file and private_key_file.filename:
        decrypted_text = rsa_decrypt(cipher_file, private_key_file, secret_pass)
        response = send_file(io.BytesIO(decrypted_text), mimetype='text/plain', as_attachment=True, download_name='decrypted.txt')
        response.headers.add('Content-Disposition', 'attachment')
        return response
    else:
        return "invalid file"       


if __name__ == '__main__':
    app.run(debug=True, threaded=True)
    