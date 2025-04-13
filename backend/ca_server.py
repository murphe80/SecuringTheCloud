
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
import os

app = Flask(__name__)

# CA root key and certificate (load or generate)
if not os.path.exists("ca_key.pem"):
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_cert = x509.CertificateBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Local CA")])
    ).issuer_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Local CA")])
    ).public_key(
        ca_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=3650)
    ).sign(ca_key, hashes.SHA256())

    with open("ca_key.pem", "wb") as f:
        f.write(ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))

    with open("ca_cert.pem", "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

else:
    with open("ca_key.pem", "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open("ca_cert.pem", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

# Endpoint to sign CSR
@app.route("/sign-csr", methods=["POST"])
def sign_csr():
    csr_pem = request.json.get("csr")
    csr = x509.load_pem_x509_csr(csr_pem.encode())

    cert = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).sign(ca_key, hashes.SHA256())

    return jsonify({"certificate": cert.public_bytes(serialization.Encoding.PEM).decode()})

if __name__ == "__main__":
    app.run(host ="127.0.0.1",port=5005)
