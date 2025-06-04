from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def __init__(self):
    pass

def load_certificate(self, path):
    with open(path, 'rb') as cert_file:
        cert_data = cert_file.read()
    return x509.load_pem_x509_certificate(cert_data, default_backend())

def load_private_key(self, path, password=None):
    with open(path, 'rb') as key_file:
        key_data = key_file.read()
    return serialization.load_pem_private_key(key_data, password=password, backend=default_backend())

def verify_certificate(self, cert, ca_cert):
    try:
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
        return True
    except Exception as e:
        print(f"[ERRO] Verificação de certificado falhou: {e}")
        return False

def get_certificate_info(self, cert):
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": cert.serial_number,
        "not_valid_before": cert.not_valid_before,
        "not_valid_after": cert.not_valid_after,
        "public_key": cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    }

def envelopar_mensagem(self, mensagem, cert_destinatario):
    chave_simetrica = os.urandom(32)
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(chave_simetrica), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    mensagem_criptografada = encryptor.update(mensagem.encode()) + encryptor.finalize()

    chave_criptografada = cert_destinatario.public_key().encrypt(
        chave_simetrica,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {
        "mensagem_criptografada": mensagem_criptografada,
        "chave_criptografada": chave_criptografada,
        "iv": iv
        }

def desenvelopar_mensagem(self, chave_privada, chave_criptografada, iv, mensagem_criptografada):
    chave_simetrica = chave_privada.decrypt(
    chave_criptografada,
    padding.OAEP(
    mgf=padding.MGF1(hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None)
                
    )

    cipher = Cipher(algorithms.AES(chave_simetrica), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    mensagem = decryptor.update(mensagem_criptografada) + decryptor.finalize()

    return mensagem.decode()
