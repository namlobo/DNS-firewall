#dns_handler.py
# dns_handler.py (or wherever you parse DNS)
def parse_dns_query(data):
    domain = ""

	# Skip IP header
    ip_header_len = (data[0] & 0x0F) * 4

	# Skip UDP header (8 bytes)
    udp_header_len = 8

	
    dns_start = ip_header_len + udp_header_len  # DNS section starts here

	# Skip DNS header (12 bytes)
    qname_start = dns_start + 12
    i = qname_start

    while i < len(data):
        length = data[i]
        if length == 0: 
              break
        i += 1
        if i + length > len(data):
            break
        try:
            domain += data[i:i + length].decode("utf-8") + "."
        except UnicodeDecodeError:
            break
        i += length

    return domain.rstrip(".")
