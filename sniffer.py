import sys
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, wrpcap

# Global list to store captured packets for PCAP export
captured_packets = []

def inspect_payload(packet):
    """
    Inspects the raw payload of a packet for sensitive plain-text strings.
    """
    if packet.haslayer(Raw):
        payload_bytes = packet[Raw].load
        try:
            # Decode bytes to text, replacing unprintable characters
            payload_text = payload_bytes.decode('utf-8', errors='ignore')
            
            # Keywords commonly found in cleartext authentication or sensitive traffic
            sensitive_keywords = ["user", "username", "pass", "password", "login", "admin", "secret"]
            
            for keyword in sensitive_keywords:
                if keyword in payload_text.lower():
                    print(f"   [🚨 ALERT] Sensitive Keyword '{keyword}' Detected in Payload!")
                    print(f"   └─ Payload Excerpt: {payload_text[:100].strip()}\n")
                    break
        except Exception:
            pass

def packet_callback(packet):
    """
    Callback function that processes every captured packet.
    """
    if packet.haslayer(IP):
        # Save packet to global list for later PCAP export
        captured_packets.append(packet)

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "OTHER"
        src_port = "-"
        dst_port = "-"

        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        # Print standard packet information
        print(f"[+] [{protocol}] {src_ip}:{src_port} --> {dst_ip}:{dst_port}")
        
        # Perform payload security inspection
        inspect_payload(packet)

def main():
    print("=" * 65)
    print("   CODEALPHA INDUSTRIAL NETWORK SNIFFER & THREAT INSPECTOR   ")
    print("=" * 65)
    print("[*] Starting packet capture with live payload detection...")
    print("[*] Press Ctrl+C to stop capture and save Wireshark (.pcap) log file.\n")

    try:
        # We set store=True implicitly via our list so we can save to file later
        sniff(prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n" + "=" * 65)
        print("[*] Stopping capture...")
        
        # Save captured packets to a .pcap file
        if captured_packets:
            pcap_file = "network_capture.pcap"
            wrpcap(pcap_file, captured_packets)
            print(f"[✔] SUCCESS: Saved {len(captured_packets)} packets to '{pcap_file}'!")
            print("[*] You can open this file in Wireshark for deep forensic analysis.")
        else:
            print("[!] No packets captured.")
            
        print("=" * 65)
        sys.exit(0)

if __name__ == "__main__":
    main()