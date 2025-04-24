import socket
import ssl

SERVER_IP = "192.168.79.2"  # replace with correct IP
SERVER_PORT = 8443

def create_ssl_connection():
    # Create a proper SSL context with certificate authentication
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile="certs/ca.crt")
    context.load_cert_chain(certfile="certs/client.crt", keyfile="certs/client.key")
    
    # Connect to the server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    
    try:
        sock.connect((SERVER_IP, SERVER_PORT))
        ssock = context.wrap_socket(sock, server_hostname="firewall.local")
        return ssock
    except Exception as e:
        print(f"[SSL CLIENT] Connection error: {e}")
        return None

def main():
    try:
        ssock = create_ssl_connection()
        if not ssock:
            return
        
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
        print(f"[SSL CLIENT] Error: {e}")
    finally:
        try:
            if 'ssock' in locals() and ssock:
                ssock.close()
        except:
            pass

if __name__ == "__main__":
    main()
