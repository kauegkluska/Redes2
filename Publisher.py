import socket

def start_publisher(topic):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('localhost', 1883))

    while True:
        msg = input(f"Digite a mensagem para enviar em '{topic}': ")
        if msg.lower() == 'exit':
            break
        sock.send(f"PUBLISH {topic} {msg}".encode())

    sock.close()

if __name__ == "__main__":
    topic = input("Digite o tópico para publicar: ")
    start_publisher(topic)
