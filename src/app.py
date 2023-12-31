from flask import Flask, request, send_file, jsonify
import io
from src.crypto_functions.rsa_handler import rsa_encrypt, rsa_decrypt
from src.crypto_functions.fernet_handler import fernet_encrypt, fernet_decrypt
from src.crypto_functions.aes_handler import aes_encrypt, aes_decrypt

app = Flask(__name__)

@app.route('/', methods=['GET'])
def start():
    return "This is root"


@app.route('/encr', methods=['GET', 'POST'])
def receive():
    algorithm = f"{request.args.get('algo')}"
    existing_key_file = request.files.get("privkey")
    secret_pass = request.form.get("pass")
    plain_file = request.files.get("file")
    if plain_file and plain_file.filename:
        if algorithm == 'rsa':
            zip_buffer = rsa_encrypt(plain_file, secret_pass, existing_key_file)
            if existing_key_file and existing_key_file.filename:
                return send_file(io.BytesIO(zip_buffer), mimetype='text/plain', as_attachment=True, download_name='cipher2.encr')
            return send_file(zip_buffer, mimetype='application/zip', as_attachment=True, download_name='encrypted.zip')          
        elif algorithm == 'fernet':
            zip_buffer = fernet_encrypt(plain_file, secret_pass, existing_key_file)
            if existing_key_file and existing_key_file.filename:
                return send_file(io.BytesIO(zip_buffer), mimetype='text/plain', as_attachment=True, download_name='cipher2.encr')
            return send_file(zip_buffer, mimetype='application/zip', as_attachment=True, download_name='encrypted.zip')          
        elif algorithm == 'aes':
            zip_buffer = aes_encrypt(plain_file, secret_pass)
            return send_file(zip_buffer, mimetype='application/zip', as_attachment=True, download_name='encrypted.zip')          
        else: 
            return "Invalid algorithm \nvalid: \n - rsa\n - fernet\n - aes"
            
    else:
        return 'invalid file'
    

@app.route('/decr', methods=['GET', 'POST'])
def send_decrypt():
    try: 
        algorithm = request.args.get("algo").lower()
        secret_pass = request.form.get("pass")
        cipher_file = request.files.get("cipher")
        private_key_file = request.files.get("privkey")
        if cipher_file and cipher_file.filename and private_key_file and private_key_file.filename:
            if algorithm == 'rsa':
                try: 
                    decrypted_text = rsa_decrypt(cipher_file, private_key_file, secret_pass)
                    response = send_file(io.BytesIO(decrypted_text), mimetype='text/plain', as_attachment=True, download_name='decrypted.txt')
                    response.headers.add('Content-Disposition', 'attachment')
                    return response
                except Exception as e:
                    return jsonify({'Error':'some error occured {}'.format(str(e))})
            elif algorithm == 'fernet':
                decrypted_text = fernet_decrypt(cipher_file, private_key_file, secret_pass)
                response = send_file(io.BytesIO(decrypted_text), mimetype='text/plain', as_attachment=True, download_name='decrypted.txt')
                response.headers.add('Content-Disposition', 'attachment')
                return response
            elif algorithm == 'aes':
                sym_key = request.files.get("symkey")
                decrypted_text = aes_decrypt(cipher_file, private_key_file, sym_key)
                response = send_file(io.BytesIO(decrypted_text), mimetype='text/plain', as_attachment=True, download_name='decrypted.txt')
                response.headers.add('Content-Disposition', 'attachment')
                return response
        else:
            return "invalid file"       
    except ValueError as e: 
        return jsonify({'error': 'Invalid key file'}), 400
    
    # except Exception as e:
    #     return jsonify({'error': 'An internal server error occurred: {} '.format(str(e))}), 500


if __name__ == '__main__':
    app.run(debug=True, threaded=True)
    