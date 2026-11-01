from scapy.all import IP,TCP
from db_handler import insert_alert

ip_port_tracker={}

def detect_port_scan(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip=packet[IP].src
        dst_ip=packet[IP].dst
        port=packet[TCP].dport

        if src_ip not in ip_port_tracker:
            ip_port_tracker[src_ip]=set()

        ip_port_tracker[src_ip].add(port)

        print(f"{src_ip} --> PORT: {port} | TOTAL PORTS: {len(ip_port_tracker[src_ip])}")

        if len(ip_port_tracker[src_ip])>5:
            insert_alert(src_ip,dst_ip,"PORT_SCAN","HIGH")  
            print(f"⚠️ ALERTE:PORT SCAN DETECTE DEPUIS {src_ip}") 
