from flask import Flask, request, jsonify
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import os 

app = Flask(__name__)

@app.route('/encrypt_file', methods=['POST'])
def encrypt_file(input_file, output_file):
    """ 
    Encrypts a given file using AES 256 encryption

    Args: 
        input_file (String) : file to be encrypted 
        output_file (String) : file for encrypted file to be written to 
    Returns: 
        key (int) : 32 bit key for decryption 
        iv (int) : 16 bit iv for decryption
       
    """

    data = request.json
    input_file = data['input_file']
    output_file = data['output_file']

    if not input_file or not output_file:
        return jsonify({"message":"Missing file paths"}), 400

    key = os.urandom(32)
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        #read file in binary mode 
        with open(input_file, "rb") as f: 
            plaintext = f.read()

        #pad contents to make multiple of 16 bytes 
        pad_plaintext = pad(plaintext)
        ciphertext = cipher.encrypt(pad_plaintext)

        with open(output_file, "wb") as f:
            f.write(ciphertext)

        # encoded_key = key.hex()
        encoded_iv = iv.hex()

        encrypted_key = encryptAES(key).hex()

        return jsonify({"message": "file encrypted successfully", "encrypted aes key":encrypted_key, "iv":encoded_iv})

    except Exception as e:
        print(f"An error occured opening the file: {e}")

def pad(data):
    """Pads data to be a multiple of 16 bytes (AES block size)."""
    pad_length = 16 - len(data) % 16
    return data + bytes([pad_length] * pad_length)


app.route('/decrypt_file', methods=['POST'])
def decrypt_file():
    """

        Decrypts file using key and iv 

        Args:
            input_file (string) : file to be decrypted 
            output_file (string) : file where plaintext is to be written to
            key (hex) : key to be used for decryption 
            iv (hex) : iv to be used for decryption

    """
    try:
        #retrieve data from request 
        data = request.json
        input_file = data['input_file']
        output_file = data['output_file']
        key = data['key']
        iv = data['iv']

        if not input_file or not output_file:
            return jsonify({"error": "Missing file paths"}), 400

        if not key or not iv:
            return jsonify({"error": "Missing key or IV"}), 400
        

        decoded_key = bytes.fromhex(key)
        decoded_iv = bytes.fromhex(iv)

        if len(decoded_key) != 32:
            return jsonify({"message": "Incorrect length for AES key"}), 400

        cipher = AES.new(decoded_key, AES.MODE_CBC, decoded_iv)

        with open(input_file, "rb") as f:
            ciphertext = f.read()

        #unpad data
        plaintext = unpad(cipher.decrypt(ciphertext))

        #write to output file 
        with open(output_file, "wb") as f:
            f.write(plaintext)
        
        return jsonify({"message":"file decrypted successfully"}), 200
        
    except Exception as e:
        print(f"An error occured decrypting the file: {e}")
        
def unpad(data):
    """unpads data from AES block size"""
    pad_length = data[-1]
    return data[:-pad_length]


def encryptAES(aes_key):
    try:
        # retrieve RSA public key 
        with open("public.pem", "rb") as f:
            public_key = RSA.import_key(f.read())
        cipher_rsa = PKCS1_OAEP.new(public_key)
        return cipher_rsa.encrypt(aes_key)
    
    except Exception as e:
        print(f"error encrypting AES key : {e}")

def decryptAES(aes_key):
    try:
        #retrieve RSA private key
        with open("private.pem", "rb") as f:
            private_key = RSA.import_key(f.read())
        cipher_rsa = PKCS1_OAEP.new(private_key)
        return cipher_rsa.decrypt(aes_key)
    except Exception as e:
        print(f"error decrypting AES key : {e}")


if __name__ == "__main__":
    app.run()