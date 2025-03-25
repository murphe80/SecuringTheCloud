from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import os 
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

import database.cloud_group

def encrypt_file(input_stream, output_file, group_name):
    """ 
    Encrypts a given file using AES 256 encryption

    Args: 
        input_file (String) : file to be encrypted 
        output_file (String) : file for encrypted file to be written to 
    Returns: 
        key (int) : 32 bit key for decryption 
        iv (int) : 16 bit iv for decryption
       
    """

    key = os.urandom(32)
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        #read contents in binary mode 
        plaintext = input_stream.encode('utf-8')

        #pad contents to make multiple of 16 bytes 
        pad_plaintext = pad(plaintext)
        ciphertext = cipher.encrypt(pad_plaintext)

        with open(output_file, "wb") as f:
            f.write(ciphertext)

        # encoded_key = key.hex()
        encoded_iv = iv.hex()

        encrypted_key = encryptAES(key, group_name).hex()

        return True

    except Exception as e:
        print(f"An error occured encrypting the file: {e}")
        return False

def pad(data):
    """Pads data to be a multiple of 16 bytes (AES block size)."""
    pad_length = 16 - len(data) % 16
    return data + bytes([pad_length] * pad_length)

def decrypt_file(input_file, output_file, key, iv):
    """

        Decrypts file using key and iv 

        Args:
            input_file (string) : file to be decrypted 
            output_file (string) : file where plaintext is to be written to
            key (hex) : key to be used for decryption 
            iv (hex) : iv to be used for decryption

    """
    try:
        
        #decrypt aes key
        decrypted_aes = decryptAES(key)

        # decoded_key = bytes.fromhex(key)
        decoded_iv = bytes.fromhex(iv)

        if len(decrypted_aes) != 32:
            print("Incorrect length for AES key")
            return False

        cipher = AES.new(decrypted_aes, AES.MODE_CBC, decoded_iv)

        with open(input_file, "rb") as f:
            ciphertext = f.read()

        #unpad data
        plaintext = unpad(cipher.decrypt(ciphertext))

        #write to output file 
        with open(output_file, "wb") as f:
            f.write(plaintext)
        
        print("file decrypted successfully")
        return True
        
    except Exception as e:
        print(f"An error occured decrypting the file: {e}")
        return False
        
def unpad(data):
    """unpads data from AES block size"""
    pad_length = data[-1]
    return data[:-pad_length]


def encryptAES(aes_key, group_name):
    try:
        # retrieve group's public key from db
        public_key_pem = database.cloud_group.retrieve_group_PK(group_name)
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return encrypted_aes_key
        return cipher_rsa.encrypt(aes_key)
    
    except Exception as e:
        print(f"error encrypting AES key : {e}")

def decryptAES(aes_key):
    try:
        #retrieve group private key
        with open("group_private.pem", "rb") as f:
            private_key = RSA.import_key(f.read())
        cipher_rsa = PKCS1_OAEP.new(private_key)
        return cipher_rsa.decrypt(aes_key)
    except Exception as e:
        print(f"error decrypting AES key : {e}")

def generateKeyPair(filename):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Save private key
    write_file = filename + ".pem"
    with open(write_file, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')  # Convert bytes to string        
    return public_key_pem