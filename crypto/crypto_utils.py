from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

class CryptoUtils:
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

    def verify_certificate(self, cert_to_verify, ca_cert):
        try:
            ca_public_key = ca_cert.public_key()
            ca_public_key.verify(
                cert_to_verify.signature,
                cert_to_verify.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert_to_verify.signature_hash_algorithm,
            )
            return True
        except Exception as e:
            print(f"[ERRO CryptoUtils] Verificação de certificado falhou: {e}")
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

    def envelopar_para_broker(self, dados_json_claros, cert_broker):
        chave_simetrica = os.urandom(32) 
        iv = os.urandom(16)

        cipher = Cipher(algorithms.AES(chave_simetrica), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        dados_criptografados = encryptor.update(dados_json_claros.encode()) + encryptor.finalize()

        chave_simetrica_criptografada_broker = cert_broker.public_key().encrypt(
            chave_simetrica,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return {
            "dados_criptografados": dados_criptografados.hex(),
            "chave_simetrica_criptografada_broker": chave_simetrica_criptografada_broker.hex(),
            "iv": iv.hex()
        }

    def desenvelopar_pelo_broker(self, chave_privada_broker, envelope_recebido):
    
        chave_simetrica_criptografada_broker = bytes.fromhex(envelope_recebido["chave_simetrica_criptografada_broker"])
        iv = bytes.fromhex(envelope_recebido["iv"])
        dados_criptografados = bytes.fromhex(envelope_recebido["dados_criptografados"])

        chave_simetrica = chave_privada_broker.decrypt(
            chave_simetrica_criptografada_broker,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        cipher = Cipher(algorithms.AES(chave_simetrica), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        dados_json = decryptor.update(dados_criptografados) + decryptor.finalize()

        return dados_json.decode()

    def criptografar_payload_e2e(self, payload_mensagem):
   
        chave_simetrica_payload = os.urandom(32)
        iv_payload = os.urandom(16)

        cipher = Cipher(algorithms.AES(chave_simetrica_payload), modes.CFB(iv_payload), backend=default_backend())
        encryptor = cipher.encryptor()
        payload_criptografado = encryptor.update(payload_mensagem.encode()) + encryptor.finalize()

        return {
            "payload_criptografado": payload_criptografado, 
            "chave_simetrica_payload": chave_simetrica_payload, 
            "iv_payload": iv_payload 
        }

    def envelopar_chave_simetrica_para_destinatario(self, chave_simetrica, cert_destinatario):
        """
        Criptografa uma chave simétrica específica para um destinatário usando sua chave pública.
        """
        chave_simetrica_criptografada = cert_destinatario.public_key().encrypt(
            chave_simetrica,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return chave_simetrica_criptografada

    def decifrar_payload_e2e(self, chave_privada_cliente, envelope_payload):
        """
        Decifra o payload de uma mensagem E2E usando a chave privada do cliente.
        """
        chave_simetrica_payload_criptografada = bytes.fromhex(envelope_payload["chave_simetrica_payload_criptografada_para_assinante"])
        iv_payload = bytes.fromhex(envelope_payload["iv_e2e"])
        payload_criptografado = bytes.fromhex(envelope_payload["payload_e2e_criptografado"])

        chave_simetrica_payload = chave_privada_cliente.decrypt(
            chave_simetrica_payload_criptografada,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        cipher = Cipher(algorithms.AES(chave_simetrica_payload), modes.CFB(iv_payload), backend=default_backend())
        decryptor = cipher.decryptor()
        payload_decifrado = decryptor.update(payload_criptografado) + decryptor.finalize()

        return payload_decifrado.decode()
