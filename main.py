from cryptography.fernet import Fernet

# Function to generate a new symmetric encryption key
def generate_key():
    return Fernet.generate_key()

# Function to save the encryption key to a file
def save_key(key, key_file):
    # Open the file in write-binary mode and save the key
    with open(key_file, 'wb') as file:
        file.write(key)

# Function to load the encryption key from a file
def load_key(key_file):
    # Open the file in read-binary mode and return the key
    with open(key_file, 'rb') as file:
        return file.read()

# Function to encrypt the contents of a file using the provided key
def encrypt_file(input_file, output_file, key):
    # Open the input file in read-binary mode and read its contents
    with open(input_file, 'rb') as file:
        data = file.read()
    
    # Create a Fernet cipher object using the provided key
    fernet = Fernet(key)
    
    # Encrypt the file data
    encrypted_data = fernet.encrypt(data)

    # Write the encrypted data to the output file in write-binary mode
    with open(output_file, 'wb') as file:
        file.write(encrypted_data)

# Function to decrypt the contents of an encrypted file using the provided key
def decrypt_file(input_file, output_file, key):
    # Open the input (encrypted) file in read-binary mode and read its contents
    with open(input_file, 'rb') as file:
        encrypted_data = file.read()

    # Create a Fernet cipher object using the provided key
    fernet = Fernet(key)
    
    # Decrypt the encrypted data
    decrypted_data = fernet.decrypt(encrypted_data)

    # Write the decrypted data to the output file in write-binary mode
    with open(output_file, 'wb') as file:
        file.write(decrypted_data)

# Main execution block
if __name__ == "__main__":
    # Generate a new encryption key
    key = generate_key()

    # Specify the filename where the key will be saved
    key_file = 'encryption_key.key'

    # Save the generated key to the key file
    save_key(key, key_file)

    # Define the input file, encrypted file, and decrypted file names
    input_file = 'plain_text.txt'      # File to be encrypted
    encrypted_file = 'encrypted_file.text'  # Where the encrypted content will be saved
    decrypted_file = 'decrypted_file.text'  # Where the decrypted content will be saved

    # Encrypt the input file and save the encrypted data to the output file
    encrypt_file(input_file, encrypted_file, key)
    print(f"File '{input_file}' encrypted to '{encrypted_file}'")

    # Decrypt the encrypted file and save the decrypted data to another file
    decrypt_file(encrypted_file, decrypted_file, key)
    print(f"File '{encrypted_file}' decrypted to '{decrypted_file}'")