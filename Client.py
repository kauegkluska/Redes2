import socket
import threading

def receive_messages(sock):
    while True:
        try:
            msg = sock.recv(1024).decode()
            print(f"[RECEBIDO] {msg}")
        except:
            break

def start_subscriber(topic):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('localhost', 1883))

    sock.send(f"SUBSCRIBE {topic}".encode())
    print(f"[CLIENTE] Assinado no tópico '{topic}'")

    thread = threading.Thread(target=receive_messages, args=(sock,))
    thread.start()

if __name__ == "__main__":
    topic = input("Digite o tópico para assinar: ")
    start_subscriber(topic)
