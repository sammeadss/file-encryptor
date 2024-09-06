# File Encryptor/Decryptor Web App

## Overview
This project is a Flask-based web application that allows users to securely encrypt and decrypt files using the AES (symmetric encryption) and RSA (asymmetric encryption) algorithms. 

### Features
- **AES Encryption (Symmetric)**: Encrypt files using AES-256 with a random initialization vector (IV) for each encryption.
- **RSA Encryption (Asymmetric)**: Encrypt files using RSA with 2048-bit key size for secure key management.
- **File Decryption**: Easily decrypt files encrypted with either AES or RSA.
- **User-Friendly Interface**: Upload files, select encryption or decryption, and download the processed files.
  
### Technologies Used
- **Flask**: Python-based web framework.
- **Python Cryptography**: Used for implementing AES and RSA encryption/decryption.
- **HTML/CSS/Bootstrap**: For front-end design.

## Getting Started

### Prerequisites
- Make sure you have Python 3.12 installed. You can download it [here](https://www.python.org/downloads/).  
- A code editor or terminal/command-line environment for running Python scripts (e.g., VSCode, PyCharm, or terminal/command prompt).

### Installation
1. **Clone the repository**:
   ```bash
   git clone https://github.com/sammeadss/file-encryptor.git
   cd file-encryptor
   ```

2. **Create a virtual environment in python terminal (optional, but recommended)**:
   ```python
   python -m venv venv
   source venv/bin/activate   # On Windows use `venv\Scripts\activate`
   ```

3. **Install the required dependencies**:
   ```python
   pip install -r requirements.txt
   ```
   
4. **Run the Flask app**:
   ```python
   python app.py
   ```

5. **Access the app**:  
   Open your web browser and input the URL displayed after the code is
   ran.
   ```python
   * Running on http://127.0.0.1:5000
   ```

### Using the App

1. **Select a file** to upload.
2. **Choose an action** (Encrypt or Decrypt).
3. **Select the encryption algorithm**:
   - **AES (Symmetric)**: AES-256 encryption with CBC mode.
   - **RSA (Asymmetric)**: RSA encryption with a 2048-bit key size.
4. **Submit** and download the processed file.

### Security Notes
- **Key files** (e.g., `aes_key.key`, `private_key.pem`) should be kept secure and are automatically generated during encryption. 

### Future Improvements
- Add user authentication for enhanced security.
- Add more encryption algorithms such as ChaCha20 or Blowfish.

### License
This project is licensed under the [MIT License](https://choosealicense.com/licenses/mit/).

### Contact

For questions or suggestions, feel free to reach out at:

- **Email**: meadss0115@gmail.com  
- **GitHub**: [sammeadss](https://github.com/sammeadss)
