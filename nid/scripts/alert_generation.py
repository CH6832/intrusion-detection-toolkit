from scapy.all import *

def alert_generator(packet):
    # Analyze packet and generate alerts for detected threats
    if threat_detected:
        # Generate alert with details about the threat
        alert_details = {"Type": "Malware Infection", "Source IP": packet[IP].src, "Destination IP": packet[IP].dst}
        print(f"Alert: {alert_details}")

# Generate alerts for detected threats in captured packets
sniff(iface="eth0", prn=alert_generator, store=0)
