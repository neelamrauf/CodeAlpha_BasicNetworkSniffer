from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    # Requirement: Analyze captured packets to understand structure [cite: 24]
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        
        # Mapping protocol numbers to names [cite: 24, 26]
        protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        protocol_name = protocol_map.get(proto, str(proto))

        # Requirement: Display source/destination IPs, protocols, and payloads [cite: 26]
        print(f"\n[+] Packet Captured:")
        print(f"    Source IP:      {src_ip}")
        print(f"    Destination IP: {dst_ip}")
        print(f"    Protocol:       {protocol_name}")
        
        # Extracting Payload [cite: 26]
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = bytes(packet.payload)
            if payload:
                # Showing first 50 characters of the payload for the analysis [cite: 24]
                print(f"    Payload:        {payload[:50]}...")

def main():
    print("--- CodeAlpha Basic Network Sniffer ---")
    print("Capturing network traffic... Press Ctrl+C to stop.")
    
    # Requirement: Capture network traffic packets [cite: 23, 25]
    # 'store=0' ensures we don't use too much RAM while sniffing
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
