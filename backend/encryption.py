import base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import os 
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from database.cloud_group import retrieve_public_key, retrieve_group_members, add_encrypted_aes_keys, retrieve_encrypted_aes, retrieve_iv
import requests
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID


def encrypt_file(input_stream, output_file, group_name, key, iv):
    """ 
    Encrypts a given file using AES 256 encryption

    Args: 
        input_file (String) : file to be encrypted 
        output_file (String) : file for encrypted file to be written to 
    Returns: 
        key (int) : 32 bit key for decryption 
        iv (int) : 16 bit iv for decryption
       
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    

    try:
        #read contents in binary mode 
        plaintext = input_stream.encode('utf-8')

        #pad contents to make multiple of 16 bytes 
        pad_plaintext = pad(plaintext)
        ciphertext = cipher.encrypt(pad_plaintext)

        with open(output_file, "wb") as f:
            f.write(ciphertext)

        # For each user encrypt aes key with their public key 
        # Create file id 
        file_id = os.urandom(16)
        file_id = base64.b64encode(file_id).decode('utf-8')
        encryptAES(key, group_name, file_id)

        return file_id

    except Exception as e:
        print(f"An error occured encrypting the file: {e}")
        return 0,0

def pad(data):
    """Pads data to be a multiple of 16 bytes (AES block size)."""
    pad_length = 16 - len(data) % 16
    return data + bytes([pad_length] * pad_length)

def decrypt_file(ciphertext, output_file, file_id, user_id, iv):
    """

        Decrypts file using key and iv 

        Args:
            input_file (string) : file to be decrypted 
            output_file (string) : file where plaintext is to be written to

    """
    try:
        
        #decrypt aes key
        decrypted_aes = decryptAES(user_id, file_id)

        # retrieve iv 
        if isinstance(iv, tuple) and len(iv) > 0:
            # Extract bytes from tuple
            decoded_iv = iv[0]
            print(f"IV extracted from tuple: {type(decoded_iv)}")
        elif isinstance(iv, str):
            decoded_iv = bytes.fromhex(iv)
        else:
            decoded_iv = iv

        if len(decrypted_aes) != 32:
            print("Incorrect length for AES key")
            return False

        cipher = AES.new(decrypted_aes, AES.MODE_CBC, decoded_iv)

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


def encryptAES(aes_key, group_name, file_id):
    try:
        # Retrieve members in group
        group_members = retrieve_group_members(group_name)
        print(f"Group members: {group_members}")
        if not group_members:
            print("No group members found")
            return
            
        # Process each group member
        for user_id in group_members:
            # Retrieve public key from database
            public_key_obj = retrieve_public_key(user_id[0])
            
            if not public_key_obj:
                print(f"No public key found for user {user_id[0]}")
                continue
                
            # Convert the public key object to PEM format if it's not already
            if isinstance(public_key_obj, str):
                # It's already a PEM string
                public_key_pem = public_key_obj
            elif hasattr(public_key_obj, 'public_bytes'):
                # It's a cryptography library key object
                public_key_pem = public_key_obj.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            else:
                print(f"Unexpected public key format for user {user_id[0]}")
                continue
                
            # Encrypt aes key with public key
            try:
                public_key = RSA.import_key(public_key_pem)
                cipher_rsa = PKCS1_OAEP.new(public_key)
                if not isinstance(aes_key, bytes):
                    aes_key = bytes(aes_key)
                    
                encrypted_key = cipher_rsa.encrypt(aes_key)
                
                # Store the encrypted key as binary
                add_encrypted_aes_keys(encrypted_key, user_id[0], file_id)
                print(f"Encrypted key stored for user {user_id[0]}")
            except Exception as e:
                print(f"Error encrypting for user {user_id[0]}: {e}")
                import traceback
                traceback.print_exc()
                
        print("Processed all encrypted aes keys")
        return
    except Exception as e:
        print(f"Error in encryptAES: {e}")
        import traceback
        traceback.print_exc()
    
    except Exception as e:
        print(f"Error encrypting AES key : {e}")

def decryptAES(user_id, file_id):
    try:
        # Retrieve encrypted aes key for user
        encrypted_key = retrieve_encrypted_aes(user_id, file_id)
        
        if not encrypted_key:
            print(f"No encrypted key found for user {user_id} and file {file_id}")
            return None


        print(f"Encrypted key retrieved, type: {type(encrypted_key)}, length: {len(encrypted_key)}")
        
        # Retrieve user's private key
        with open("private.pem", "rb") as f:
            private_key_data = f.read()
            
        try:
            private_key = RSA.import_key(private_key_data)
            cipher_rsa = PKCS1_OAEP.new(private_key)
            decrypted_key = cipher_rsa.decrypt(encrypted_key)
            print(f"Successfully decrypted key, length: {len(decrypted_key)}")
            return decrypted_key
        except Exception as e:
            print(f"Error during RSA decryption: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    except Exception as e:
        print(f"Error in decryptAES: {e}")
        import traceback
        traceback.print_exc()
        return None
    
    except Exception as e:
        print(f"Error decrypting AES key: {e}")
        import traceback
        traceback.print_exc()
        return None

def generate_key_and_csr(user_id):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    private_key_pem = key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()) 
    
    #store private key locally
    with open("private.pem", "wb") as f:
        f.write(private_key_pem)

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, str(user_id)),
    ])).sign(key, hashes.SHA256())

    # Send CSR to CA server
    response = requests.post("http://localhost:5005/sign-csr", json={
        "csr": csr.public_bytes(serialization.Encoding.PEM).decode()
    }, proxies={"http":None, "https":None})

    cert_pem = response.json()["certificate"]

    print(f"Generated key and certificate for {user_id}")
    return cert_pem
