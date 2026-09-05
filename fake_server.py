import socket

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", 8080))
server.listen(5)

print("Fake server listening on 127.0.0.1:8080...")

while True:
    client_socket, addr = server.accept()
    print(f"Connection from {addr}")
    try:
        client_socket.sendall(b"Apache/2.4.49\n")
    except Exception:
        pass
    finally:
        client_socket.close()