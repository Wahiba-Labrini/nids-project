from scapy.all import ARP
from db_handler import insert_alert

ip_mac_tracker={}

def detect_arp_spoofing(packet):
    if packet.haslayer(ARP):
        src_ip=packet[ARP].psrc 
        src_mac=packet[ARP].hwsrc
        if src_ip  in ip_mac_tracker:
            if ip_mac_tracker[src_ip]==src_mac :
                insert_alert(src_ip,src_mac,"ARP_SPOOFING","CRITICAL")   
                print(f"⚠️ ALERTE: ARP SPOOFING DETECTE POUR {src_ip}")
            else:
                ip_mac_tracker[src_ip]!=src_mac 
