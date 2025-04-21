# server/ssl_server.py
import socket, ssl

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="certs/cert.pem", keyfile="certs/key.pem")

bind_socket = socket.socket()
bind_socket.bind(("0.0.0.0", 8443))
bind_socket.listen(5)
print("[SSL SERVER] Listening on port 8443...")

while True:
    client_sock, addr = bind_socket.accept()
    with context.wrap_socket(client_sock, server_side=True) as ssock:
        print(f"[SSL SERVER] Connection from {addr}")
        data = ssock.recv(1024).decode()
        print(f"[SSL SERVER] Received command: {data}")
        # Placeholder logic: just respond with "ACK"
        ssock.send(b"ACK")
