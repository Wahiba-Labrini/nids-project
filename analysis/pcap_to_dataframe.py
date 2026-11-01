from scapy.all import TCP,IP,time


def transfrom_to_dataframe(pcap):
    dataframe=[]
    for packet in pcap:
        if packet.haslayer(TCP) and packet.haslayer(IP):
            is_syn= 'S' == str(packet[TCP].flags)  
            data={
            "src_ip":packet[IP].src,
            "dst_ip":packet[IP].dst,
            "port":packet[TCP].dport,
            "timestamp":float(packet.time),
            "SYN":is_syn 
            }
            dataframe.append(data)
    return dataframe
    
   