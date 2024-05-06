from scapy.all import *

def signature_detector(packet):
    # Define signatures for known threats
    known_signatures = {"SELECT * FROM users WHERE": "Potential SQL Injection Attack",
                        "<script>": "Possible XSS Attack"}

    # Check if packet payload matches any known signatures
    for signature, description in known_signatures.items():
        if signature in str(packet):
            print(f"Alert: {description} detected!")

# Detect known threats in captured packets
sniff(iface="eth0", prn=signature_detector, store=0)
