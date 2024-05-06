from scapy.all import *

def load_rules():
    # Load signature-based detection rules from rules/snort.rules
    with open("rules/snort.rules", "r") as rules_file:
        return [rule.strip() for rule in rules_file.readlines()]

def signature_detector(packet, rules):
    # Check if packet payload matches any known signatures
    for rule in rules:
        if rule in str(packet):
            print(f"Alert: Signature match - {rule}")

# Load signature-based detection rules
signature_rules = load_rules()

# Detect known threats in captured packets
sniff(iface="eth0", prn=lambda pkt: signature_detector(pkt, signature_rules), store=0)
