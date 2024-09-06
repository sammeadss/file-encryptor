from flask import Flask, render_template, request, send_file
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import hashes, serialization, padding
from cryptography.hazmat.backends import default_backend
import os

app = Flask(__name__)

# Ensure the uploads directory exists
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

### AES Helper Functions ###
def aes_encrypt(input_file, output_file, key):
    iv = os.urandom(16)  # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(input_file, 'rb') as f:
        data = f.read()

    # Padding data for AES block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_file, 'wb') as f:
        f.write(iv + encrypted_data)

def aes_decrypt(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        iv = f.read(16)  # Read the initialization vector
        encrypted_data = f.read()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding after decryption
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    with open(output_file, 'wb') as f:
        f.write(decrypted_data)

### RSA Helper Functions ###
def generate_rsa_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_rsa_keys(private_key, public_key):
    with open('private_key.pem', 'wb') as private_file:
        private_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    with open('public_key.pem', 'wb') as public_file:
        public_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

def load_rsa_keys():
    with open('private_key.pem', 'rb') as private_file:
        private_key = serialization.load_pem_private_key(
            private_file.read(),
            password=None,
            backend=default_backend()
        )
    
    with open('public_key.pem', 'rb') as public_file:
        public_key = serialization.load_pem_public_key(
            public_file.read(),
            backend=default_backend()
        )
    
    return private_key, public_key

def rsa_encrypt(input_file, output_file, public_key):
    with open(input_file, 'rb') as file:
        data = file.read()
    
    encrypted_data = public_key.encrypt(
        data,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    with open(output_file, 'wb') as file:
        file.write(encrypted_data)

def rsa_decrypt(input_file, output_file, private_key):
    with open(input_file, 'rb') as file:
        encrypted_data = file.read()
    
    decrypted_data = private_key.decrypt(
        encrypted_data,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    with open(output_file, 'wb') as file:
        file.write(decrypted_data)

### Flask Route for File Encryption/Decryption ###
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        action = request.form['action']
        algorithm = request.form['algorithm']
        file = request.files['file']

        input_file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(input_file_path)

        output_file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'output_' + file.filename)

        if action == 'encrypt':
            if algorithm == 'aes':
                key = os.urandom(32)  # AES 256-bit key
                with open('aes_key.key', 'wb') as key_file:
                    key_file.write(key)
                aes_encrypt(input_file_path, output_file_path, key)
                return send_file(output_file_path, as_attachment=True, download_name='encrypted_' + file.filename)

            elif algorithm == 'rsa':
                private_key, public_key = generate_rsa_key()
                save_rsa_keys(private_key, public_key)
                rsa_encrypt(input_file_path, output_file_path, public_key)
                return send_file(output_file_path, as_attachment=True, download_name='encrypted_' + file.filename)

        elif action == 'decrypt':
            if algorithm == 'aes':
                with open('aes_key.key', 'rb') as key_file:
                    key = key_file.read()
                aes_decrypt(input_file_path, output_file_path, key)
                return send_file(output_file_path, as_attachment=True, download_name='decrypted_' + file.filename)

            elif algorithm == 'rsa':
                private_key, public_key = load_rsa_keys()
                rsa_decrypt(input_file_path, output_file_path, private_key)
                return send_file(output_file_path, as_attachment=True, download_name='decrypted_' + file.filename)

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)