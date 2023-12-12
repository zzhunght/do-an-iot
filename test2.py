from scapy.all import sniff, IP

def process_packet(packet):
    if IP in packet:
        
        print("Packet Duration:", packet.summary())
        print("Packet sent time: ", packet[IP].time - packet.time )

sniff(prn=process_packet, iface='VMware Virtual Ethernet Adapter for VMnet8')
