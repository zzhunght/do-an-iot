import pyshark
from scapy.all import *

def capture_and_save_packets(interface, output_file, packet_count=10):
    # Bắt gói tin trên interface và lưu vào file pcap
    capture = pyshark.LiveCapture(interface=interface, output_file=output_file)
    # Bắt số lượng gói tin được chỉ định
    capture.sniff(packet_count=packet_count)



def capture_and_save_packets2(interface, output_file, packet_count=10):
    # Bắt gói tin trên interface và lưu vào file pcap
    packets = sniff(iface=interface, count=packet_count)
    wrpcap(output_file, packets)

if __name__ == "__main__":
    interface = "Wi-Fi"  # Thay thế bằng tên interface của bạn (ví dụ: "eth0" trên Linux)
    output_file = "pcap_temp/captured_packets.pcap"

    # Bắt và lưu 10 gói tin vào file pcap
    # capture_and_save_packets(interface, output_file, packet_count=10)
    capture_and_save_packets2(interface, output_file, packet_count=10)
