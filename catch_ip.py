from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP
import numpy as np
ip_source_counters = {}

# biến global theo dõi flow
flows = {}

def process_packet(packet):
    print('packet: ', packet)
    try:
        # Kiểm tra xem gói tin có lớp IP không
        global  flows,ip_source_counters
        # if packet.haslayer(IP) and packet[IP].dst == '10.251.1.43':
        # if packet.haslayer(IP) and packet[IP].dst == '192.168.127.130':
        if packet.haslayer(IP):
            source_ip = packet[IP].src
            print(packet[IP])
            # Lấy các giá trị cụ thể từ gói tin
            duration = packet[IP].ttl
            flow_duration = 0
            rate = 0
            if flow_duration > 0:
                rate = len(packet) / duration
            header_length = packet[IP].ihl * 32
            protocol_type = packet[IP].proto
            # Các trường khác tương tự
            packet_size = len(packet)
            # Tính toán các thông tin
            total_size = 0
            min_size = 0
            max_size = 0
            iat = 0
            number_of_packets = 1
            list_of_packets = []

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
            if packet.haslayer(TCP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[TCP].sport
                destination_port = packet[TCP].dport
                # Xây dựng flow ID dựa trên thông tin lấy được
                sorted_pair1 = sorted([(src_ip, src_port), (dst_ip, destination_port)])
                # Xây dựng flow ID dựa trên thông tin đã sắp xếp
                flow_id = f"{sorted_pair1[0][0]}_{sorted_pair1[0][1]}_{sorted_pair1[1][0]}_{sorted_pair1[1][1]}_tcp"
                # Kiểm tra xem flow đã tồn tại trong obj
                if flow_id in flows:
                    # Nếu tồn tại, cập nhật thông tin về flow và tính toán duration
                    flows[flow_id]['total_packet'] += packet_size
                    flows[flow_id]['number_of_packets'] += 1
                    flows[flow_id]['list_of_packets'].append(packet_size)
                    flow_duration = packet.time - flows[flow_id]['start_time']
                    total_size = flows[flow_id]['total_packet']
                    min_size = min(packet_size,flows[flow_id]['min'])
                    max_size = max(packet_size,flows[flow_id]['max'])
                    number_of_packets = flows[flow_id]['number_of_packets']
                    list_of_packets = flows[flow_id]['list_of_packets']
                    flows[flow_id]['prev_time'] = packet.time
                    iat = packet.time - flows[flow_id]['prev_time'] 
                else:
                    # Nếu chưa tồn tại, thêm mới thông tin về flow
                    flows[flow_id] = {
                        'total_packet': packet_size, 
                        'number_of_packets' : 1,
                        'list_of_packets' : [packet_size],
                        'start_time': packet.time, 
                        'prev_time': packet.time, 
                        'min': packet_size,
                        'max': packet_size,
                        # 'incoming': [packet_size],
                        # 'outgoing': [packet_size],
                    }
                    iat = packet.time
                    total_size = packet_size
                    min_size = packet_size
                    max_size = packet_size
                    list_of_packets = flows[flow_id]['list_of_packets']
                tcp = 1
                if destination_port == 80:
                    http = 1
                elif destination_port == 443:
                    https = 1

                ip_source_counters[source_ip] = ip_source_counters.get(source_ip, {'ack': 0, 'syn': 0, 'fin': 0, 'urg': 0, 'rst': 0})


                if packet[TCP].flags.A:
                    ip_source_counters[source_ip]['ack'] += 1
                    ack_flag = 1
                if packet[TCP].flags.S:
                    ip_source_counters[source_ip]['syn'] += 1
                    syn_flag = 1
                if packet[TCP].flags.F:
                    ip_source_counters[source_ip]['fin'] += 1
                    fin_flag = 1
                if packet[TCP].flags.U:
                    ip_source_counters[source_ip]['urg'] += 1
                if packet[TCP].flags.R:
                    ip_source_counters[source_ip]['rst'] += 1
                    rst_flag = 1
                if packet[TCP].flags.P:
                    psh_flag=1
                
                

            if packet.haslayer(UDP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[UDP].sport
                destination_port = packet[UDP].dport
                # Xây dựng flow ID dựa trên thông tin lấy được
                sorted_pair1 = sorted([(src_ip, src_port), (dst_ip, destination_port)])
                # Xây dựng flow ID dựa trên thông tin đã sắp xếp
                flow_id = f"{sorted_pair1[0][0]}_{sorted_pair1[0][1]}_{sorted_pair1[1][0]}_{sorted_pair1[1][1]}_UDP"
                # Kiểm tra xem flow đã tồn tại trong obj
                if flow_id in flows:
                    # Nếu tồn tại, cập nhật thông tin về flow và tính toán duration
                    flows[flow_id]['total_packet'] += packet_size
                    flows[flow_id]['number_of_packets'] += 1
                    flows[flow_id]['list_of_packets'].append(packet_size)
                    flow_duration = packet.time - flows[flow_id]['start_time']
                    total_size = flows[flow_id]['total_packet']
                    min_size = min(packet_size,flows[flow_id]['min'])
                    max_size = max(packet_size,flows[flow_id]['max'])
                    number_of_packets = flows[flow_id]['number_of_packets']
                    list_of_packets = flows[flow_id]['list_of_packets']
                    flows[flow_id]['prev_time'] = packet.time
                    iat = packet.time - flows[flow_id]['prev_time'] 
                else:
                    # Nếu chưa tồn tại, thêm mới thông tin về flow
                    flows[flow_id] = {
                        'total_packet': packet_size, 
                        'number_of_packets' : 1,
                        'list_of_packets' : [packet_size],
                        'start_time': packet.time, 
                        'prev_time': packet.time, 
                        'min': packet_size,
                        'max': packet_size,
                        # 'incoming': [packet_size],
                        # 'outgoing': [packet_size],
                    }
                    iat = packet.time
                    total_size = packet_size
                    min_size = packet_size
                    max_size = packet_size
                    list_of_packets = flows[flow_id]['list_of_packets']
                # cờ cua udp
                udp  = 1 
            if packet.haslayer(ICMP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[ICMP].sport
                destination_port = packet[ICMP].dport
                # Xây dựng flow ID dựa trên thông tin lấy được
                sorted_pair1 = sorted([(src_ip, src_port), (dst_ip, destination_port)])
                # Xây dựng flow ID dựa trên thông tin đã sắp xếp
                flow_id = f"{sorted_pair1[0][0]}_{sorted_pair1[0][1]}_{sorted_pair1[1][0]}_{sorted_pair1[1][1]}_ICMP"
                # Kiểm tra xem flow đã tồn tại trong obj
                if flow_id in flows:
                    # Nếu tồn tại, cập nhật thông tin về flow và tính toán duration
                    flows[flow_id]['total_packet'] += packet_size
                    flows[flow_id]['number_of_packets'] += 1
                    flows[flow_id]['list_of_packets'].append(packet_size)
                    flow_duration = packet.time - flows[flow_id]['start_time']
                    total_size = flows[flow_id]['total_packet']
                    min_size = min(packet_size,flows[flow_id]['min'])
                    max_size = max(packet_size,flows[flow_id]['max'])
                    number_of_packets = flows[flow_id]['number_of_packets']
                    list_of_packets = flows[flow_id]['list_of_packets']
                    flows[flow_id]['prev_time'] = packet.time
                    iat = packet.time - flows[flow_id]['prev_time'] 
                else:
                    # Nếu chưa tồn tại, thêm mới thông tin về flow
                    flows[flow_id] = {
                        'total_packet': packet_size, 
                        'number_of_packets' : 1,
                        'list_of_packets' : [packet_size],
                        'start_time': packet.time, 
                        'prev_time': packet.time, 
                        'min': packet_size,
                        'max': packet_size,
                        # 'incoming': [packet_size],
                        # 'outgoing': [packet_size],
                    }
                    iat = packet.time
                    total_size = packet_size
                    min_size = packet_size
                    max_size = packet_size
                    list_of_packets = flows[flow_id]['list_of_packets']
                # cờ cua icmp
                icmp  = 1 

            # In các giá trị
            avg = total_size / number_of_packets if number_of_packets > 0 else packet_size
            # tính variance
            variance = np.var(list_of_packets)
            covariance = np.cov(list_of_packets, list_of_packets)[0, 1]
            print("Flow Duration:", flow_duration)
            print("Header Length:", header_length)
            print("Protocol Type:", protocol_type)
            print("Duration:", duration)
            print("Rate:", rate)
            print("FIN Flag:", fin_flag)
            print("SYN Flag:", syn_flag)
            print("RST Flag:", rst_flag)
            print("PSH Flag:", psh_flag)
            print("ACK Flag:", ack_flag)
            print('HTTP Flag:', http)
            print('HTTPS Flag:', https)
            print('TCP Flag:', tcp)
            print('UDP Flag:', udp)
            print('ICMP Flag:', http)
            print("TotSum:", total_size)
            print("Min:", min_size)
            print("Max:", max_size)
            print("AVG:", avg)
            print("Std:", np.std(list_of_packets) if number_of_packets > 1 else packet_size)
            print("Tot size:", packet_size)
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
                total_size,  # You have "TotSum" printed twice, replace this with the correct value
                min_size,
                max_size,
                avg,
                np.std(list_of_packets) if number_of_packets > 1 else packet_size,
                packet_size,  # Assuming packet_size is defined somewhere in your code
            ]
            print('input ___ : ', model_input)
            # In giá trị của các cờ

            # print("IAT:", iat)
            # print("Number:", number_of_packets)
            # print("Magnitue:", np.sqrt((avg *2)))
            # print("Radius:", np.sqrt(variance *2))
            # print("Covariance:", covariance)
            # print("Variance:", variance)
            # print("Weight:", total_size * (total_size / number_of_packets) if number_of_packets > 0 else 0)
            print('========================================================================================')
    
    except Exception as e:
        print('Exception:', e)
    
sniff(prn=process_packet,iface='VMware Virtual Ethernet Adapter for VMnet8')