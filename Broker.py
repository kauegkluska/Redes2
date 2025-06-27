import socket
import threading
import json
from crypto.crypto_utils import CryptoUtils
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

clients = {} 
topics = {}  
history = {}
crypto = CryptoUtils()

broker_private_key = crypto.load_private_key("certs/broker_key.pem", password=None)

broker_cert = crypto.load_certificate("certs/broker_cert.pem")

ca_cert = crypto.load_certificate("certs/ca_cert.pem")

def enviar_json(conn, data):
    """Auxiliar para enviar dados JSON serializados."""
    try:
        mensagem = json.dumps(data).encode()
        conn.sendall(mensagem)
    except Exception as e:
        print(f"[BROKER ERRO] Falha ao enviar mensagem para {conn.getpeername()}: {e}")

def enviar_historico(conn, topic):
    """Envia o histórico de mensagens criptografadas E2E para um novo assinante."""
    if topic in history:
        for msg_blob in history[topic]:
            try:
                cert_subscriber = clients[conn]["cert"]
                
                chave_simetrica_payload = broker_private_key.decrypt(
                    bytes.fromhex(msg_blob["chave_simetrica_payload_criptografada_para_broker"]),
                    padding.OAEP(
                        mgf=padding.MGF1(hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

              
                chave_simetrica_payload_criptografada_para_assinante = crypto.envelopar_chave_simetrica_para_destinatario(
                    chave_simetrica_payload,
                    cert_subscriber
                ).hex()

                pacote = {
                    "command": "HISTORY",
                    "topic": topic,
                    "payload_e2e_criptografado": msg_blob["payload_e2e_criptografado"],
                    "iv_e2e": msg_blob["iv_e2e"],
                    "chave_simetrica_payload_criptografada_para_assinante": chave_simetrica_payload_criptografada_para_assinante
                }
                enviar_json(conn, pacote)
            except Exception as e:
                print(f"[BROKER ERRO] Falha ao enviar item de histórico E2E para {conn.getpeername()}: {e}")

def handle_client(conn, addr):
    print(f"[BROKER] Nova conexão de {addr}")

    try:
        certificado_bytes = conn.recv(4096)
        cert_cliente = x509.load_pem_x509_certificate(certificado_bytes)

        if not crypto.verify_certificate(cert_cliente, ca_cert):
            print(f"[BROKER] [ERRO Autenticação] Certificado inválido de {addr}. Conexão encerrada.")
            conn.close()
            return

        print(f"[BROKER] Certificado de {addr} verificado com sucesso. Cliente autenticado.")
        clients[conn] = {
            "addr": addr,
            "cert": cert_cliente
        }

        while True:
            data = conn.recv(8192)
            if not data:
                print(f"[BROKER] Conexão encerrada por {addr}")
                break

            envelope_serializado_recebido = json.loads(data.decode())

            mensagem_json_decifrada_pelo_broker = crypto.desenvelopar_pelo_broker(
                chave_privada_broker=broker_private_key,
                envelope_recebido=envelope_serializado_recebido
            )
            packet = json.loads(mensagem_json_decifrada_pelo_broker)
            command = packet.get("command")
            topic = packet.get("topic")

            if command == "SUBSCRIBE":
                if topic not in topics:
                    topics[topic] = []
                if conn not in topics[topic]:
                    topics[topic].append(conn)
                    print(f"[BROKER] {addr} assinou o tópico '{topic}'")
                    enviar_historico(conn, topic)
                else:
                    print(f"[BROKER] {addr} já estava assinando o tópico '{topic}'")

            elif command == "PUBLISH":
                payload_e2e_criptografado = bytes.fromhex(packet["payload_e2e_criptografado"])
                iv_e2e = bytes.fromhex(packet["iv_e2e"])
                chave_simetrica_payload_criptografada_para_broker = bytes.fromhex(packet["chave_simetrica_payload_criptografada_para_broker"])

                chave_simetrica_payload = broker_private_key.decrypt(
                    chave_simetrica_payload_criptografada_para_broker,
                    padding.OAEP(
                        mgf=padding.MGF1(hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                if topic not in history:
                    history[topic] = []
         
                history[topic].append({
                    "payload_e2e_criptografado": payload_e2e_criptografado.hex(),
                    "iv_e2e": iv_e2e.hex(),
                    "chave_simetrica_payload_criptografada_para_broker": chave_simetrica_payload_criptografada_para_broker.hex()
                })

                print(f"[BROKER] Mensagem (payload E2E) recebida para tópico '{topic}'. Roteando para assinantes...")

                if topic in topics:
                    for subscriber_conn in topics[topic]:
                        if subscriber_conn == conn: 
                            continue
                        try:
                            cert_subscriber = clients[subscriber_conn]["cert"]

                            
                            chave_simetrica_payload_criptografada_para_assinante = crypto.envelopar_chave_simetrica_para_destinatario(
                                chave_simetrica_payload,
                                cert_subscriber
                            ).hex()

                            pacote_para_assinante = {
                                "command": "MESSAGE",
                                "topic": topic,
                                "payload_e2e_criptografado": payload_e2e_criptografado.hex(),
                                "iv_e2e": iv_e2e.hex(),
                                "chave_simetrica_payload_criptografada_para_assinante": chave_simetrica_payload_criptografada_para_assinante
                            }
                            enviar_json(subscriber_conn, pacote_para_assinante)
                            print(f"[BROKER] Payload E2E encaminhado para {clients[subscriber_conn]['addr']}")

                        except Exception as e:
                            print(f"[BROKER ERRO] Falha ao encaminhar payload E2E para {clients[subscriber_conn]['addr']}: {e}")
                           
                            if subscriber_conn in topics[topic]:
                                topics[topic].remove(subscriber_conn)

            else:
                print(f"[BROKER] Comando desconhecido de {addr}: {command}")

    except json.JSONDecodeError as e:
        print(f"[BROKER ERRO] Erro ao decodificar JSON de {addr}: {e} - Dados: {data.decode(errors='ignore')[:100]}...")
    except Exception as e:
        print(f"[BROKER ERRO] Erro inesperado na conexão com {addr}: {e}")

    finally:
        print(f"[BROKER] Conexão finalizada com {addr}")
        for t, subs in topics.items():
            if conn in subs:
                subs.remove(conn)
        clients.pop(conn, None)
        conn.close()

def start_broker():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 1883))
    server.listen(5)
    print("[BROKER] Aguardando conexões na porta 1883...")

    try:
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[BROKER] Servidor encerrado pelo usuário.")
    finally:
        server.close()

if __name__ == "__main__":
    start_broker()