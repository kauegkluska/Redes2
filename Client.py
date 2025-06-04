import socket
import threading
import json

def receber_mensagens(sock):
    while True:
        try:
            data = sock.recv(1024).decode()
            if not data:
                print("[CLIENTE] Conexão encerrada pelo servidor.")
                break

            packet = json.loads(data)
            command = packet.get("command")

            if command == "TOPICS_LIST":
                print(f"[CLIENTE] Tópicos disponíveis: {packet.get('topics')}")
            elif command == "MESSAGE":
                print(f"\n[MSG RECEBIDA] [{packet['topic']}] {packet['message']}")
            elif command == "HISTORY":
                print(f"\n[HISTÓRICO] [{packet['topic']}] {packet['message']}")
            else:
                print(f"\n[CLIENTE] Mensagem inesperada: {packet}")

        except Exception as e:
            print(f"[ERRO] Recebendo mensagem: {e}")
            break

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('localhost', 1883))
    print("[CLIENTE] Conectado ao broker MQTT")

    threading.Thread(target=receber_mensagens, args=(sock,), daemon=True).start()

    while True:
        print("\nEscolha uma opção:")
        print("1 - Assinar um tópico")
        print("2 - Publicar mensagem em tópico")
        print("exit - Sair")
        escolha = input("> ").strip()

        if escolha == "1":
            topico = input("Digite o tópico para assinar: ").strip()
            pacote = {
                "command": "SUBSCRIBE",
                "topic": topico
            }
            sock.send(json.dumps(pacote).encode())
            print(f"[CLIENTE] Solicitação para assinar tópico '{topico}' enviada.")

        elif escolha == "2":
            topico = input("Digite o tópico para publicar: ").strip()
            mensagem = input(f"Digite a mensagem para enviar no tópico '{topico}': ").strip()
            pacote = {
                "command": "PUBLISH",
                "topic": topico,
                "message": mensagem
            }
            sock.send(json.dumps(pacote).encode())
            print(f"[CLIENTE] Mensagem enviada para tópico '{topico}'.")

        elif escolha.lower() == "exit":
            print("[CLIENTE] Encerrando conexão...")
            sock.close()
            break

        else:
            print("[CLIENTE] Opção inválida, tente novamente.")

if __name__ == "__main__":
    main()
