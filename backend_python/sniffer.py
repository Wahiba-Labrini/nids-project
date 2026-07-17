from scapy.all import sniff,IP,TCP,ARP
from db_handler import insert_alert

ip_port_tracker={}
ip_mac_tracker={}
brute_force_tracker={}

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

def detect_arp_spoofing(packet):
    if packet.haslayer(ARP):
        src_ip=packet[ARP].psrc 
        src_mac=packet[ARP].hwsrc
        if src_ip  in ip_mac_tracker:
            if ip_mac_tracker[src_ip]!=src_mac :
                insert_alert(src_ip,src_mac,"ARP_SPOOFING","CRITICAL")   
                print(f"⚠️ ALERTE: ARP SPOOFING DETECTE POUR {src_ip}")
            else:
                ip_mac_tracker[src_ip]!=src_mac 

def detect_brute_force(packet):
    if packet.haslayer(IP)and  packet.haslayer(TCP):
        src_ip=packet[IP].src
        dst_ip=packet[IP].dst
        port=packet[TCP].dport

        key=f"{src_ip}_{dst_ip}_{port}"

        if key not in brute_force_tracker:
            brute_force_tracker[key]=1    
        else:
            brute_force_tracker[key]+=1

        if brute_force_tracker[key] > 10:
            insert_alert(src_ip,dst_ip,"BRUTE_FORCE","HIGH")
            print(f"⚠️ ALERTE: BRUTE FORCE DECETE DEPUIS {src_ip} VERS {dst_ip}:{port}")


def process_packet( packet):
    detect_port_scan(packet)
    detect_arp_spoofing(packet)
    detect_brute_force(packet)
sniff(prn=process_packet,count=50)


        