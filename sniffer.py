from scapy.all import sniff, TCP, UDP, ICMP, IP, Raw
import time
import signal

# handle Ctrl+C interruption
def signal_handler(sig, frame):
    print("\nProgram interrupted by user.")
    raise SystemExit(0)

signal.signal(signal.SIGINT, signal_handler)

# Function to process captured packets
def process_packet(packet):
    try:
        # Check if the packet contains an IP layer
        if packet.haslayer(IP):
            print(f"\nPacket captured at {time.ctime()}:")

            # Display source and destination IPs
            print(f"  Source IP: {packet[IP].src}")
            print(f"  Destination IP: {packet[IP].dst}")

            # Check for TCP layer
            if packet.haslayer(TCP):
                print("  Protocol: TCP")
                print(f"    Source Port: {packet[TCP].sport}")
                print(f"    Destination Port: {packet[TCP].dport}")
                print(f"    Flags: {packet[TCP].flags}")

            # Check for UDP layer
            elif packet.haslayer(UDP):
                print("  Protocol: UDP")
                print(f"    Source Port: {packet[UDP].sport}")
                print(f"    Destination Port: {packet[UDP].dport}")

            # Check for ICMP layer
            elif packet.haslayer(ICMP):
                print("  Protocol: ICMP")
                print(f"    Type: {packet[ICMP].type}")
                print(f"    Code: {packet[ICMP].code}")

            # Check for raw payload data
            if packet.haslayer(Raw):
                try:
                    payload = packet[Raw].load.decode()  # Attempt to decode payload
                    print(f"  Payload: {payload}")
                except UnicodeDecodeError:
                    print("  Payload: [Non-printable binary data]")

    except Exception as e:
        print(f"Error processing packet: {e}")

# Log packets to a file for later analysis
def log_packet(packet):
    with open("packets.log", "a") as log_file:
        log_file.write(packet.summary() + "\n")

# Start sniffing with enhanced functionality
print("Starting packet sniffing. Press Ctrl+C to stop.")
sniff(prn=process_packet, store=False, iface="eth0")
