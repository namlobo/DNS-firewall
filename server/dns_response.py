
#dns_response.py
import socket
import struct

def checksum(data):
    """Calculate Internet Checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def build_dns_response(query, decision, client_ip, client_port):
    transaction_id = query[:2]
    flags = b"\x81\x80" if decision == "ALLOWED" else b"\x81\x83"  # 0x8183 = NXDOMAIN
    qdcount = b"\x00\x01"
    ancount = b"\x00\x01" if decision == "ALLOWED" else b"\x00\x00"
    nscount = b"\x00\x00"
    arcount = b"\x00\x00"

    header = transaction_id + flags + qdcount + ancount + nscount + arcount

    question = query[12:]  # Original question section
    response = header + question

    if decision == "ALLOWED":
        domain_parts = question[:-4].split(b'\x00')[0]  # domain name with labels
        name = b"\xc0\x0c"  # Pointer to domain name
        type_a = b"\x00\x01"
        class_in = b"\x00\x01"
        ttl = b"\x00\x00\x00\x1e"  # 30 seconds
        rdlength = b"\x00\x04"
        rdata = socket.inet_aton("1.2.3.4")  # Fake resolved IP address

        answer = name + type_a + class_in + ttl + rdlength + rdata
        response += answer

    return response

def send_dns_response(send_sock, query, client_ip, client_port, decision):
	# DNS payload
	dns_payload = build_dns_response(query, decision, client_ip, client_port)

	# UDP Header
	src_port = 53
	length = 8 + len(dns_payload)
	checksum_udp = 0
	udp_header = struct.pack("!HHHH", src_port, client_port, length, checksum_udp)

	# IP Header
	version_ihl = (4 << 4) + 5
	tos = 0
	total_length = 20 + len(udp_header) + len(dns_payload)
	identification = 54321
	flags_offset = 0
	ttl = 64
	protocol = socket.IPPROTO_UDP
	checksum_ip = 0
	src_ip = socket.inet_aton("192.168.231.2")  # Server's IP (your DNS server IP)
	dst_ip = socket.inet_aton(client_ip)

	ip_header = struct.pack("!BBHHHBBH4s4s",
                        	version_ihl, tos, total_length, identification,
                        	flags_offset, ttl, protocol, checksum_ip, src_ip, dst_ip)

	checksum_ip = checksum(ip_header)
	ip_header = struct.pack("!BBHHHBBH4s4s",
                        	version_ihl, tos, total_length, identification,
                        	flags_offset, ttl, protocol, checksum_ip, src_ip, dst_ip)

	# Final packet
	packet = ip_header + udp_header + dns_payload

	# Send the packet
	send_sock.sendto(packet, (client_ip, 0))
	print(f"[+] Sent DNS response ({decision}) to {client_ip}:{client_port}")
