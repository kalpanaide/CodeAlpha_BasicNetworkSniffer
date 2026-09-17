import sys
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, wrpcap

captured_packets = []
MAX_PACKETS = 30  # Auto-stop after capturing 30 packets!

def packet_callback(packet):
    if packet.haslayer(IP):
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

        print(f"[{len(captured_packets)}/{MAX_PACKETS}] [{protocol}] {src_ip}:{src_port} --> {dst_ip}:{dst_port}")

def main():
    print("=" * 65)
    print("   CODEALPHA INDUSTRIAL NETWORK SNIFFER & THREAT INSPECTOR   ")
    print("=" * 65)
    print(f"[*] Capturing {MAX_PACKETS} live packets and auto-saving to PCAP...\n")

    # count parameter stops sniffing automatically after 30 packets!
    sniff(prn=packet_callback, count=MAX_PACKETS, store=False)

    print("\n" + "=" * 65)
    print("[*] Capture Complete!")
    if captured_packets:
        pcap_file = "network_capture.pcap"
        wrpcap(pcap_file, captured_packets)
        print(f"[✔] SUCCESS: Saved {len(captured_packets)} packets to '{pcap_file}'!")
    print("=" * 65)

if __name__ == "__main__":
    main()