# client/ssl_client.py
import socket, ssl

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE  # Allow self-signed

SERVER_IP = "192.168.79.186"  # 🔁 Change this to your firewall server's IP

with socket.create_connection((SERVER_IP, 8443)) as sock:
    with context.wrap_socket(sock, server_hostname="firewall.local") as ssock:
        print("[SSL CLIENT] Connected to server.")
        command = input("Enter control command (e.g., 'GET_LOGS'): ")
        ssock.send(command.encode())
        response = ssock.recv(1024)
        print("[SSL CLIENT] Response:", response.decode())
