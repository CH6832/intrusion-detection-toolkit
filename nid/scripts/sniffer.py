from scapy.all import sniff

def packet_handler(packet):
    print(packet.summary())

# Capture packets on the specified interface
sniff(iface="eth0", prn=packet_handler, store=0)
