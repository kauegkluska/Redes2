from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta

def gerar_ca():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"Broker CA")
    ])
    cert = x509.CertificateBuilder().subject_name(subject)\
        .issuer_name(issuer)\
        .public_key(key.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.utcnow())\
        .not_valid_after(datetime.utcnow() + timedelta(days=365))\
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)\
        .sign(key, hashes.SHA256())

    with open("certs/ca_key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    with open("certs/ca_cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def assinar_certificado_cliente(nome_cliente):
    with open("certs/ca_key.pem", "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    with open("certs/ca_cert.pem", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nome_cliente)])

    cert = x509.CertificateBuilder().subject_name(subject)\
        .issuer_name(ca_cert.subject)\
        .public_key(key.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.utcnow())\
        .not_valid_after(datetime.utcnow() + timedelta(days=365))\
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)\
        .sign(ca_key, hashes.SHA256())

    with open(f"certs/{nome_cliente}_key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    with open(f"certs/{nome_cliente}_cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

# Execução
gerar_ca()
assinar_certificado_cliente("cliente2")
