import socket
import struct
import sys

DNS_SERVER = "10.74.27.3"  # replace with your actual server IP
PORT = 53

def build_query(domain):
    query = b"\xaa\xaa"  # Transaction ID
    query += b"\x01\x00"  # Standard query with recursion
    query += b"\x00\x01\x00\x00\x00\x00\x00\x00"  # 1 question, 0 answer, 0 authority, 0 additional
    for part in domain.split("."):
        query += struct.pack("B", len(part)) + part.encode()
    query += b"\x00"         # End of domain name
    query += b"\x00\x01"     # Type A
    query += b"\x00\x01"     # Class IN
    return query

def parse_response(data):
    flags = data[2:4]
    if flags == b'\x81\x80':
        return "ALLOWED"
    elif flags == b'\x81\x83':
        return "BLOCKED"
    else:
        return "UNKNOWN"

def query_domain(domain):
    query = build_query(domain)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)

    try:
        sock.sendto(query, (DNS_SERVER, PORT))
        data, _ = sock.recvfrom(512)
        return parse_response(data)
    except socket.timeout:
        return "TIMEOUT"
    except Exception as e:
        return f"ERROR: {e}"
    finally:
        sock.close()

def main():
    if len(sys.argv) > 1:
        domain = sys.argv[1].strip()
        result = query_domain(domain)
        print(result)
        return

    while True:
        print("\nChoose an option:")
        print("1. Enter domain")
        print("2. Exit")
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            domain = input("Enter domain to resolve: ").strip()
            result = query_domain(domain)
            print(f"The entered domain name - {domain} is {result.lower()}.")
        elif choice == "2":
            print("Exiting client.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()

