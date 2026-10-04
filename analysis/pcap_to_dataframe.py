from scapy.all import TCP,IP

def  transfrom_to_dataframe(pcap):
    dataframe=[]
    for packet in pcap:
        if packet.haslayer(TCP) and packet.haslayer(IP):
            data={"src_ip":packet[IP].src,
            "dst_ip":packet[IP].dst,
            "port":packet[TCP].dport
            }
            dataframe.append(data)
    return dataframe
    
   