import pyshark
caps = pyshark.FileCapture('wifitest.pcapng')
from pyshark.tshark import tshark
import numpy as np

from datetime import datetime

layer_ip_fields = [
    'version', 'hdr_len', 'dsfield', 
    'dsfield_dscp', 'dsfield_ecn', 'len', 
    'id', 'flags', 'flags_rb', 'flags_df', 
    'flags_mf', 'frag_offset', 'ttl', 'proto', 
    'checksum', 'checksum_status', 'src', 
    'addr', 'src_host', 'host', 'dst', 'dst_host'
]

layer_eth_fields = [
    'dst', 'dst_resolved', 
    'dst_oui','dst_oui_resolved', 
    'addr', 'addr_resolved', 
    'addr_oui','addr_oui_resolved', 
    'dst_lg','lg','dst_ig', 'ig', 'src', 
    'src_resolved','src_oui', 'src_oui_resolved', 
    'src_lg','src_ig', 'type', 'padding'
]

layer_tcp_fields = [
    'srcport', 'dstport', 'port', 'stream', 
    'completeness', 'completeness_rst', 'completeness_fin', 
    'completeness_data', 'completeness_ack', 'completeness_syn_ack', 
    'completeness_syn', 'completeness_str', 'len', 
    'seq', 'seq_raw', 'nxtseq', 'ack', '_ws_expert', 
    'ack_nonzero', '_ws_expert_message', 
    '_ws_expert_severity', '_ws_expert_group', 
    'ack_raw', 'hdr_len', 'flags', 'flags_res', 'flags_ae', 
    'flags_cwr', 'flags_ece', 'flags_urg', 'flags_ack', 
    'flags_push', 'flags_reset', 'flags_syn', 'flags_fin', 
    'flags_str', 'window_size_value', 'window_size', 'window_size_scalefactor', 
    'checksum', 'checksum_status', 
    'urgent_pointer', '', 'time_relative', 'time_delta'
]

layer_udp = [
    'srcport', 'dstport', 'port', 'length', 
    'checksum', 'checksum_status', 'stream', '', 
    'time_relative', 'time_delta', 'payload'
]
layer_data_fields = ['data', 'data_data', 'data_len']


# for packet in caps:
    #Xử lý gói tin ở đây
    # print(packet)
    # if 'data' in packet:
    #     print(packet['data'].field_names)
    # if 'tcp' in packet:
    #     # print(packet['tcp'].time_delta)
    #     print('fin flag ', packet['tcp'].flags_fin)
        
    #     print(packet['tcp'].time_relative)
    # print(packet['tls'].field_names)
    # if 'udp' in packet:
    #     print(float(packet['udp'].time_delta) )
# interfaces = tshark.get_all_tshark_interfaces_names()

# # In ra thông tin của mỗi interface
# for interface in interfaces:
#     print(f"Interface: {interface}")


tcp_flows = {}
udp_flows = {}
def process_packet(packet):
    if 'ip' in packet:
        global tcp_flows, udp_flows
        packet_size = len(packet)


        #--------------------------
        ongoing_in_flows = []
        incoming_in_flows = []
        packets_in_flows = []

        #--------------------------
        min_size = packet_size
        max_size = packet_size
        std = 0
        tot_size = len(packet)
        tot_sum = len(packet)
        protocol_type = packet['ip'].proto
        rate = 0

        #-------------------------
        duration = packet['ip'].ttl
        flow_duration = 0
        header_length = 0
        iat = 0

        #PORT --------------------------------
        http = 0
        https = 0
        icmp = 0
        tcp = 0
        udp = 0
        fin_flag = 0
        syn_flag = 0
        rst_flag = 0
        psh_flag = 0
        ack_flag = 0

        if 'tcp' in packet:
            src_ip = packet['ip'].src
            dst_ip = packet['ip'].dst
            src_port = packet['tcp'].srcport
            dst_port = packet['tcp'].dstport

            iat = packet['tcp'].time_delta if float(packet['tcp'].time_delta) > 0.0 else datetime.now().timestamp()
            tcp = 1
            if dst_port == 443:
                https = 1
            if dst_port == 80:
                http = 1
            
            if packet['tcp'].flags_fin == True:
                fin_flag = 1
            if packet['tcp'].flags_syn == True:
                syn_flag = 1
            if packet['tcp'].flags_res == True:
                rst_flag = 1
            if packet['tcp'].flags_push == True:
                psh_flag = 1
            if packet['tcp'].flags_ack == True:
                ack_flag = 1

            # Xây dựng flow ID dựa trên thông tin lấy được
            sorted_pair1 = sorted([(src_ip, src_port), (dst_ip, dst_port)])
            # Xây dựng flow ID dựa trên thông tin đã sắp xếp
            flow_id = f"{sorted_pair1[0][0]}_{sorted_pair1[0][1]}_{sorted_pair1[1][0]}_{sorted_pair1[1][1]}_tcp"
            
            # kiểm tra xem flow đã được record lại chưa
            if flow_id in tcp_flows:
                tcp_flows[flow_id]['tot_sum'] += len(packet)
                tcp_flows[flow_id]['packets'].append(len(packet))
                tcp_flows[flow_id]['flow_duration'] = packet['tcp'].time_relative
                
                if src_ip == sorted_pair1[0][0]:
                    tcp_flows[flow_id]['incoming'].append(len(packet))
                else:
                    tcp_flows[flow_id]['ongoing'].append(len(packet))

                min_size = min(packet_size,tcp_flows[flow_id]['min'])
                max_size = max(packet_size,tcp_flows[flow_id]['max'])
            else:
                tcp_flows[flow_id] = {
                    'tot_sum': packet_size,
                    'packets': [packet_size],
                    'flow_duration': packet['tcp'].time_relative,
                    'incoming': [packet_size],
                    'ongoing': [],
                    'min': packet_size,
                    'max': packet_size
                }
                

            tot_sum  = tcp_flows[flow_id]['tot_sum']
            ongoing_in_flows = tcp_flows[flow_id]['ongoing']
            incoming_in_flows = tcp_flows[flow_id]['incoming']
            packets_in_flows = tcp_flows[flow_id]['packets']
            flow_duration = tcp_flows[flow_id]['flow_duration']

        if 'udp' in packet:
            udp = 1
            src_ip = packet['ip'].src
            dst_ip = packet['ip'].dst
            src_port = packet['udp'].srcport
            dst_port = packet['udp'].dstport
            iat = packet['udp'].time_delta if float(packet['udp'].time_delta) > 0.0 else datetime.now().timestamp() / 10
            # Xây dựng flow ID dựa trên thông tin lấy được
            sorted_pair1 = sorted([(src_ip, src_port), (dst_ip, dst_port)])
            # Xây dựng flow ID dựa trên thông tin đã sắp xếp
            flow_id = f"{sorted_pair1[0][0]}_{sorted_pair1[0][1]}_{sorted_pair1[1][0]}_{sorted_pair1[1][1]}_udp"

            if flow_id in udp_flows:
                udp_flows[flow_id]['tot_sum'] += len(packet)
                udp_flows[flow_id]['packets'].append(len(packet))
                udp_flows[flow_id]['flow_duration'] = packet['udp'].time_relative
                
                if src_ip == sorted_pair1[0][0]:
                    udp_flows[flow_id]['incoming'].append(len(packet))
                else:
                    udp_flows[flow_id]['ongoing'].append(len(packet))

                min_size = min(packet_size,udp_flows[flow_id]['min'])
                max_size = max(packet_size,udp_flows[flow_id]['max'])
            else:
                udp_flows[flow_id] = {
                    'tot_sum': packet_size,
                    'packets': [packet_size],
                    'flow_duration': packet['udp'].time_relative,
                    'incoming': [packet_size],
                    'ongoing': [],
                    'min': packet_size,
                    'max': packet_size
                }
                

            tot_sum  = udp_flows[flow_id]['tot_sum']
            ongoing_in_flows = udp_flows[flow_id]['ongoing']
            incoming_in_flows = udp_flows[flow_id]['incoming']
            packets_in_flows = udp_flows[flow_id]['packets']
            flow_duration = udp_flows[flow_id]['flow_duration']
        # tính toán
        avg_size = tot_sum / len(packets_in_flows) if len(packets_in_flows)  > 0 else packet_size
        std = np.std(packets_in_flows)
        magnitude = (
            np.average(ongoing_in_flows if len(ongoing_in_flows) > 0 else [0]) + 
            np.average(incoming_in_flows if len(incoming_in_flows) > 0 else [0])
        ) ** 0.5

        radius = (
            np.var(ongoing_in_flows if len(ongoing_in_flows) > 0 else [0]) + 
            np.var(incoming_in_flows if len(incoming_in_flows) > 0 else [0])
        ) ** 0.5
        covariance = np.cov(packets_in_flows if len(packets_in_flows) > 0 else [0])
        variance_in = np.var(incoming_in_flows if len(incoming_in_flows) > 0 else [0])
        variance_out = np.var(ongoing_in_flows if len(ongoing_in_flows) > 0 else [0])
        variance = variance_in / variance_out if variance_out > 0 else 0

        covariance = float(covariance if covariance else 0)
        model_input = [
            flow_duration,
            header_length,
            protocol_type,
            duration,
            rate,
            fin_flag,
            syn_flag,
            rst_flag,
            psh_flag,
            ack_flag,
            http,
            https,
            tcp,
            udp,
            icmp,
            tot_sum, 
            min_size,
            max_size,
            avg_size,
            std,
            tot_size,
            iat,
            magnitude,
            radius,
            covariance,
            variance
        ]

        print('model_input', model_input)

cap = pyshark.LiveCapture(interface='Wi-Fi')
for packet in cap.sniff_continuously():
    # Xử lý gói tin ở đây
    process_packet(packet)