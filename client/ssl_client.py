import socket
import ssl

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

SERVER_IP = "10.74.27.3"  # replace with correct IP
SERVER_PORT = 8443

try:
    with socket.create_connection((SERVER_IP, SERVER_PORT)) as sock:
        with context.wrap_socket(sock, server_hostname="firewall.local") as ssock:
            print("[SSL CLIENT] Connected to server.")

            while True:
                command = input("Enter control command (e.g., 'GET_LOGS', 'BLOCK_DOMAIN example.com', or 'exit'): ").strip()

                if command.lower() == "exit":
                    print("[SSL CLIENT] Exiting.")
                    break

                if not command:
                    print("[SSL CLIENT] Please enter a valid command.")
                    continue

                ssock.send(command.encode())
                response = ssock.recv(8192)

                try:
                    decoded = response.decode().strip()
                    print("[SSL CLIENT] Response:\n", decoded)
                except UnicodeDecodeError:
                    print("[SSL CLIENT] Failed to decode response from server.")

except Exception as e:
    print(f"[SSL CLIENT] Connection error: {e}")

