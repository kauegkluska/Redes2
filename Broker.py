import socket
import threading
import json

clients = {} 
topics = {}
history = {}  

def enviar_json(conn, data):
    try:
        mensagem = json.dumps(data).encode()
        conn.sendall(mensagem)
    except Exception as e:
        print(f"[ERRO] Falha ao enviar mensagem: {e}")

def enviar_historico(conn, topic):
    if topic in history:
        for msg in history[topic]:
            pacote = {
                "command": "HISTORY",
                "topic": topic,
                "message": msg
            }
            enviar_json(conn, pacote)

def handle_client(conn, addr):
    print(f"[BROKER] Nova conexão de {addr}")
    clients[conn] = addr

    initial_message = {
        "command": "TOPICS_LIST",
        "topics": list(topics.keys())
    }
    enviar_json(conn, initial_message)

    try:
        while True:
            print("Digite 'exit' para encerrar a conexão.")
            
            data = conn.recv(1024).decode()
            if not data:
                print(f"[BROKER] Conexão encerrada por {addr}")
                break

            packet = json.loads(data)
            command = packet.get("command")
            topic = packet.get("topic")
            message = packet.get("message", "")

            if command == "SUBSCRIBE":
                if topic not in topics:
                    topics[topic] = []
                if conn not in topics[topic]:
                    topics[topic].append(conn)
                print(f"[BROKER] {addr} assinou o tópico '{topic}'")

                enviar_historico(conn, topic)

            elif command == "PUBLISH":
                if topic not in history:
                    history[topic] = []
                history[topic].append(message)

                if topic not in topics:
                    topics[topic] = []  

                if topic in topics:
                    pacote = {
                        "command": "MESSAGE",
                        "topic": topic,
                        "message": message
                    }
                    assinantes = topics[topic].copy()
                    for subscriber in assinantes:
                        try:
                            enviar_json(subscriber, pacote)
                        except Exception:
                            print(f"[BROKER] Removendo assinante inativo {clients.get(subscriber)} do tópico '{topic}'")
                            topics[topic].remove(subscriber)

                print(f"[BROKER] Mensagem publicada em '{topic}': {message}")

    except Exception as e:
        print(f"[ERRO] {addr} - {e}")
    
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
    print("[BROKER] Aguardando conexões...")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        thread.start()

if __name__ == "__main__":
    start_broker()
