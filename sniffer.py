from scapy.all import sniff, IP, TCP

# A list of suspicious keywords to look for in packet payloads
THREAT_KEYWORDS = [b"password", b"login", b"admin", b"root"]

def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Check for suspicious keywords in the payload
        if packet.haslayer(TCP) and packet.haslayer('Raw'):
            payload = packet['Raw'].load
            for word in THREAT_KEYWORDS:
                if word in payload.lower():
                    print(f"[ALERT] Potential credential leak detected from {src_ip}!")
        
        print(f"[INFO] Packet: {src_ip} -> {dst_ip}")

print("--- Professional Network Threat Inspector v1.0 ---")
sniff(prn=packet_callback, count=20, store=False)