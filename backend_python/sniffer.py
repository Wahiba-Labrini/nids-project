from scapy.all import sniff,IP
from db_handler import insert_alert
def process_packet( packet):
    #print(packet.summary())print resume ready and now we are do that manuel
    if packet.haslayer(IP) :
        src_ip=packet[IP].src
        dst_ip=packet[IP].dst
        print(f"SOURCE: {src_ip}--> DESTINATION: {dst_ip}")
        insert_alert(src_ip,dst_ip,"TEST CAPTURE","LOW")
sniff(prn=process_packet,count=10)


        