# CodeAlpha - Basic Network Sniffer & Threat Inspector

A Python-based network analysis tool built using Scapy that captures live network traffic, decodes packet headers, scans payloads for unencrypted sensitive keywords, and exports data to Wireshark-compatible PCAP files.

## Features
- Real-time packet sniffing for IPv4, TCP, UDP, and ICMP protocols.
- Deep Packet Inspection (DPI) detecting cleartext credentials (passwords, logins).
- Export captured traffic directly to `.pcap` files for forensic analysis in Wireshark.

## Requirements
- Python 3.12+
- Scapy (`pip install scapy`)
- Npcap driver (Windows)

## How to Run
1. Run terminal/PowerShell as Administrator.
2. Execute: `python sniffer.py`
3. Stop capture and generate PCAP log using `Ctrl + C`.