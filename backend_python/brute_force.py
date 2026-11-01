from scapy.all import IP,TCP,ARP
from db_handler import insert_alert

brute_force_tracker={}

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
