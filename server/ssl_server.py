#server/ssl_server.py
import socket
import ssl
import json
import threading
import os
from datetime import datetime

BLACKLIST_FILE = os.path.join("data", "blacklist.json")

CERT_FILE = "certs/server.crt"
KEY_FILE = "certs/server.key"
CA_FILE = "certs/ca.crt"
HOST = "0.0.0.0"
PORT = 8443
LOG_FILE = "ssl_command_logs.json"


def load_blacklist():
    try:
        with open(BLACKLIST_FILE, "r") as f:
            return set(json.load(f))
    except (FileNotFoundError, json.JSONDecodeError):
        return set()

def save_blacklist(blacklist):
    with open(BLACKLIST_FILE, "w") as f:
        json.dump(sorted(list(blacklist)), f, indent=2)

def log_command(entry):
    try:
        with open(LOG_FILE, "a") as f:
            json.dump(entry, f)
            f.write("\n")  # ensure newline after each JSON object
            f.flush()      # flush to file immediately
    except Exception as e:
        print(f"[!] Error logging command: {e}")
def normalize(domain):
    return domain.lower().rstrip(".")

def handle_command(command, addr):
    timestamp = datetime.now().isoformat()
    entry = {"timestamp": timestamp, "client": addr[0], "command": command}
    log_command(entry)

    if command == "GET_LOGS":
        try:
            with open(LOG_FILE, "r") as f:
                logs = [json.loads(line) for line in f.readlines() if line.strip()]
            recent_logs = logs[-10:] if logs else []
            return "Recent Logs:\n" + json.dumps(recent_logs, indent=2)

        except FileNotFoundError:
            return "No logs available."
        except json.JSONDecodeError as e:
            return f"Error reading logs: {e}"

    elif command.startswith("BLOCK_DOMAIN"):
        parts = command.split()
        if len(parts) == 2:
            domain = parts[1]
            domain = normalize(domain)
            blacklist = load_blacklist()
            blacklist.add(domain)
            save_blacklist(blacklist)
            return f"Domain '{domain}' blocked."
        else:
            return "Usage: BLOCK_DOMAIN <domain>"

    elif command.startswith("UNBLOCK_DOMAIN"):
        parts = command.split()
        if len(parts) == 2:
            domain = parts[1]
            domain = normalize(domain)
            blacklist = load_blacklist()
            if domain in blacklist:
                blacklist.remove(domain)
                save_blacklist(blacklist)
                return f"Domain '{domain}' unblocked."
            else:
                return f"Domain '{domain}' is not in blocklist."
        else:
            return "Usage: UNBLOCK_DOMAIN <domain>"
   
     

    elif command == "SHUTDOWN":
        return "__SHUTDOWN__"

    else:
        return f"Unknown command: {command}"

def handle_client(client_sock, addr):
    try:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        context.load_verify_locations(cafile=CA_FILE)
        context.verify_mode = ssl.CERT_REQUIRED
        
        with context.wrap_socket(client_sock, server_side=True) as ssock:
            print(f"[SSL SERVER] Secure connection from {addr}")
            
            # Verify client certificate
            client_cert = ssock.getpeercert()
            if not client_cert:
                ssock.send(b"Unauthorized: No client certificate provided.")
                return
            
            subject = dict(x[0] for x in client_cert['subject'])
            cn = subject.get('commonName')
            if cn != "AuthorizedClient":
                ssock.send(b"Unauthorized client.")
                return
                
            print(f"[SSL SERVER] Authenticated client: {cn}")

            while True:
                try:
                    data = ssock.recv(1024)
                    if not data:
                        print(f"[SSL SERVER] Client {addr} disconnected.")
                        break

                    command = data.decode().strip()
                    print(f"[SSL SERVER] Received command: {command}")

                    response = handle_command(command, addr)

                    if response == "__SHUTDOWN__":
                        ssock.send(b"Server shutting down...")
                        print("[SSL SERVER] Shutting down...")
                        return True  # Signal to shutdown
                    else:
                        ssock.send(response.encode())

                except Exception as e:
                    error_msg = f"Error processing command: {e}"
                    print(f"[SSL SERVER] {error_msg}")
                    try:
                        ssock.send(error_msg.encode())
                    except:
                        pass
                    break
    except ssl.SSLError as e:
        print(f"[SSL SERVER] SSL Error with {addr}: {e}")
    except Exception as e:
        print(f"[SSL SERVER] Error handling client {addr}: {e}")
    finally:
        try:
            client_sock.close()
        except:
            pass
    
    return False  # Don't shutdown

def start_ssl_server():
    bind_socket = socket.socket()
    bind_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bind_socket.bind((HOST, PORT))
    bind_socket.listen(5)
    print(f"[SSL SERVER] Listening securely on port {PORT}...")

    shutdown_requested = False
    
    try:
        while not shutdown_requested:
            try:
                client_sock, addr = bind_socket.accept()
                client_thread = threading.Thread(
                    target=lambda: handle_client(client_sock, addr),
                    daemon=True
                )
                client_thread.start()
            except Exception as e:
                print(f"[SSL SERVER] Error accepting connection: {e}")
                
    except KeyboardInterrupt:
        print("\n[SSL SERVER] Server interrupted and shutting down.")
    finally:
        try:
            bind_socket.close()
        except:
            pass
        print("[SSL SERVER] Server stopped.")

if __name__ == "__main__":
    start_ssl_server()
