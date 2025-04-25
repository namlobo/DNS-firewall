import socket
import struct
import threading
import os
import json
from dns_handler import parse_dns_query
from inspect import inspect_domain
from dns_response import send_dns_response
from logger import log_domain
from ssl_server import start_ssl_server

WHITELIST_PATH = os.path.join("data", "whitelist.json")
BLACKLIST_PATH = os.path.join("data", "blacklist.json")
PORT = 53  # DNS port

def load_list(path):
    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        return []
    with open(path, "r") as f:
        return json.load(f)

def save_list(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def normalize(domain):
    return domain.lower().rstrip(".")

def handle_domain(domain):
    domain = normalize(domain)

    # Reload blacklist and whitelist every time for dynamic updates
    blacklist = load_list(BLACKLIST_PATH)
    whitelist = load_list(WHITELIST_PATH)

    if domain in blacklist:
        log_domain(domain, True, "[BLACKLIST]")
        return "BLOCKED"
    elif domain in whitelist:
        log_domain(domain, False, "[WHITELIST]")
        return "ALLOWED"

    is_malicious, reason = inspect_domain(domain)
    log_domain(domain, is_malicious, reason)

    if is_malicious:
        if domain not in blacklist:
            blacklist.append(domain)
            save_list(BLACKLIST_PATH, blacklist)
            print(f"[+] Added to blacklist: {domain}")
        return "BLOCKED"
    else:
        if domain not in whitelist:
            whitelist.append(domain)
            save_list(WHITELIST_PATH, whitelist)
            print(f"[+] Added to whitelist: {domain}")
        return "ALLOWED"

def start_dns_firewall():
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    recv_sock.bind(("0.0.0.0", PORT))

    send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    print("[+] DNS Firewall Server listening on port 53 (Raw Socket)")

    while True:
        try:
            data, addr = recv_sock.recvfrom(512)
            client_ip = addr[0]
            client_port = 53  # fallback default

            if len(data) > 28:
                udp_header = data[20:28]
                client_port = struct.unpack("!HHHH", udp_header)[0]

            domain = parse_dns_query(data)
            if domain:
                print(f"[*] Received DNS query from {client_ip} for: {domain}")
                decision = handle_domain(domain)
                print(f"[*] Domain: {domain} --> {decision}")
                send_dns_response(send_sock, data[28:], client_ip, client_port, decision)

        except Exception as e:
            print(f"[!] Error handling packet: {e}")

if __name__ == "__main__":
    os.makedirs("certs", exist_ok=True)

    ssl_thread = threading.Thread(target=start_ssl_server, daemon=True)
    ssl_thread.start()
    print("[+] SSL Command Server started in background thread")

    start_dns_firewall()

