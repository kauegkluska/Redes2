import socket
import threading
import json
from crypto.crypto_utils import CryptoUtils 
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

def receber_mensagens(sock, crypto, cliente_private_key):
    """Função para thread que recebe mensagens do broker."""
    while True:
        try:
            data = sock.recv(8192)
            if not data:
                print("[CLIENTE] Conexão encerrada pelo servidor.")
                break

            packet_recebido = json.loads(data.decode())

            command = packet_recebido.get("command")
            topic = packet_recebido.get("topic")

            if command == "MESSAGE" or command == "HISTORY":
                if "payload_e2e_criptografado" in packet_recebido and \
                   "chave_simetrica_payload_criptografada_para_assinante" in packet_recebido and \
                   "iv_e2e" in packet_recebido:

                    try:
                        mensagem_decifrada_payload = crypto.decifrar_payload_e2e(
                            chave_privada_cliente=cliente_private_key,
                            envelope_payload=packet_recebido
                        )
                        print(f"\n[{command} RECEBIDA] [{topic}] (E2E) {mensagem_decifrada_payload}")
                    except Exception as e:
                        print(f"\n[CLIENTE ERRO] Falha ao decifrar mensagem E2E para o tópico [{topic}]: {e}")
                else:
                    print(f"\n[CLIENTE] Mensagem recebida em formato inesperado ou não E2E para {command}: {packet_recebido.get('message', 'Sem mensagem clara')}")
            else:
                print(f"\n[CLIENTE] Mensagem inesperada: {packet_recebido}")

        except json.JSONDecodeError as e:
            print(f"[CLIENTE ERRO] Erro ao decodificar JSON recebido: {e} - Dados: {data.decode(errors='ignore')[:100]}...")
        except Exception as e:
            print(f"[CLIENTE ERRO] Recebendo mensagem: {e}")
            break

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(('localhost', 1883))
    except ConnectionRefusedError:
        print("[CLIENTE] Erro: Conexão recusada. O broker pode não estar em execução ou na porta correta.")
        return

    print("Qual é o seu nome de usuário?")
    username = input("> ").strip()
    print("Qual é a sua senha?")
    senha = input("> ").strip()

    crypto = CryptoUtils()

    cliente_private_key = None
    cliente_cert = None
    ca_cert_para_cliente = crypto.load_certificate("certs/ac_cert.pem") 

    if (username == "cliente1" and senha == "senha123"):
        cliente_cert = crypto.load_certificate("certs/cliente1_cert.pem")
        cliente_private_key = crypto.load_private_key("certs/cliente1_key.pem", password=None)
    elif (username == "cliente2" and senha == "senha456"):
        cliente_cert = crypto.load_certificate("certs/cliente2_cert.pem")
        cliente_private_key = crypto.load_private_key("certs/cliente2_key.pem", password=None)
    else:
        print("[CLIENTE] Nome de usuário ou senha inválidos. Encerrando.")
        sock.close()
        return

    if cliente_cert is None or cliente_private_key is None:
        print("[CLIENTE] Erro ao carregar certificado/chave privada do cliente. Encerrando.")
        sock.close()
        return

    sock.sendall(cliente_cert.public_bytes(serialization.Encoding.PEM))
    print("[CLIENTE] Certificado enviado para o broker.")

    broker_cert = crypto.load_certificate("certs/broker_cert.pem")

    # TODO: 
    if not crypto.verify_certificate(broker_cert, ca_cert_para_cliente):
        print("[CLIENTE ERRO] Certificado do broker inválido ou não assinado pela CA. Conexão encerrada.")
        sock.close()
        return
    else:
        print("[CLIENTE] Certificado do broker verificado com sucesso.")

    print("[CLIENTE] Conectado e autenticado ao broker.")

    threading.Thread(target=receber_mensagens, args=(sock, crypto, cliente_private_key), daemon=True).start()

    while True:
        print("\nEscolha uma opção:")
        print("1 - Assinar um tópico")
        print("2 - Publicar mensagem em tópico")
        print("exit - Sair")
        escolha = input("> ").strip()

        pacote = None 

        if escolha == "1":
            topico = input("Digite o tópico para assinar: ").strip()
            pacote = {
                "command": "SUBSCRIBE",
                "topic": topico
            }

        elif escolha == "2":
            topico = input("Digite o tópico para publicar: ").strip()
            mensagem_clara_payload = input(f"Digite a mensagem para enviar no tópico '{topico}': ").strip()

    
            e2e_payload_data = crypto.criptografar_payload_e2e(mensagem_clara_payload)
            payload_e2e_criptografado_bin = e2e_payload_data["payload_criptografado"]
            chave_simetrica_payload_bin = e2e_payload_data["chave_simetrica_payload"]
            iv_e2e_bin = e2e_payload_data["iv_payload"]

      
            chave_simetrica_payload_criptografada_para_broker_bin = crypto.envelopar_chave_simetrica_para_destinatario(
                chave_simetrica_payload_bin,
                broker_cert
            )

            pacote = {
                "command": "PUBLISH",
                "topic": topico,
                "payload_e2e_criptografado": payload_e2e_criptografado_bin.hex(),
                "iv_e2e": iv_e2e_bin.hex(),
                "chave_simetrica_payload_criptografada_para_broker": chave_simetrica_payload_criptografada_para_broker_bin.hex()
            }
            print("[CLIENTE] Payload criptografado E2E. Preparando para enviar ao broker.")

        elif escolha.lower() == "exit":
            print("[CLIENTE] Encerrando conexão...")
            sock.close()
            break

        else:
            print("[CLIENTE] Opção inválida, tente novamente.")
            continue

        if pacote:
            json_pacote = json.dumps(pacote)
            envelope_para_broker = crypto.envelopar_para_broker(json_pacote, broker_cert)

            sock.sendall(json.dumps(envelope_para_broker).encode())
            print("[CLIENTE] Mensagem enviada para o broker (com canal seguro e payload E2E se for PUBLISH).")

if __name__ == "__main__":
    main()