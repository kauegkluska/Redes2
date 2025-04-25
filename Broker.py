import socket
import threading

clients = {}
topics = {}

def handle_client(conn, addr):
    print(f"[BROKER] Nova conexão de {addr}")
    try:
        while True:
            data = conn.recv(1024).decode()
            if not data:
                break
            command, topic, *msg = data.split(" ", 2)
            message = msg[0] if msg else ""

            if command == "SUBSCRIBE":
                if topic not in topics:
                    topics[topic] = []
                topics[topic].append(conn)
                print(f"[BROKER] {addr} se inscreveu no tópico '{topic}'")
            elif command == "PUBLISH":
                if topic in topics:
                    for subscriber in topics[topic]:
                        try:
                            subscriber.send(f"{topic}: {message}".encode())
                        except:
                            topics[topic].remove(subscriber)
                    print(f"[BROKER] Mensagem enviada em '{topic}': {message}")
    except Exception as e:
        print(f"[ERRO] {e}")
    finally:
        conn.close()

def start_broker():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 1883))
    server.listen(5)
    print("[BROKER] Aguardando conexões...")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    start_broker()
