# Minipy - API-Based Encryption System

Minipy is an API-based encryption system that supports various encryption algorithms, providing a secure and flexible solution for encrypting and decrypting files.

## Table of Contents

- [Installation](#Installation)
- [Usage](#Usage)
  - [Encryption](#Encryption)
  - [Decryption](#Decryption)
- [Contributing](#Contributing)
- [License](#License)


## Installation

1. Clone the repo:

```bash
git clone git@github.com:Dark-Kernel/minipy.git && cd minipy
```

2. Create virtual env

```bash
python -m venv env
source env/bin/activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Run the API

```bash
flask run 
```


## Usage

Available algorithms:

- RSA
- Fernet
- AES ( with ECC encryption )


### Encryption:

1. RSA 


```bash
curl -F "file=@<plain.file>" -F "pass=password" "http://localhost:5000/encr?algo=rsa" -OJ
```

If you want to encrypt another file with same private key you have:
```bash
curl -F "file=@<another.file>" -F "pass=password" -F "privkey=@key.pem" "http://localhost:5000/encr?algo=rsa" -OJ
```


2. Fernet

```bash
curl -F "file=@<plain.file>" -F "pass=password" "http://localhost:5000/encr?algo=fernet" -OJ
```
```bash
curl -F "file=@<another.file>" -F "pass=password" -F "privkey=@key.pem" "http://localhost:5000/encr?algo=fernet" -OJ
```

3. AES

```bash
curl -F "file=@<plain.file>" -F "pass=password" "http://localhost:5000/encr?algo=aes" -OJ
```


### Decryption:

1. RSA

```bash
curl -F "cipher=@cipher.encr" -F "privkey=@key.pem" -F "pass=password" "http://localhost:5000/decr?algo=rsa" -OJ
```

2. Fernet

```bash
curl -F "cipher=@cipher.encr" -F "privkey=@key.pem" -F "pass=password" "http://localhost:5000/decr?algo=fernet" -OJ
```

3. AES

```bash
curl -F "cipher=@cipher.encr" -F "privkey=@key.pem" -F "symkey=@sym_key.pem" "http://localhost:5000/decr?algo=aes" -OJ
```

## Contributing

Feel free to contribute to this project. 


## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
