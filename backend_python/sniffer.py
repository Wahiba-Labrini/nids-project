from scapy.all import sniff

from port_scan import detect_port_scan
from arp_spoofing import detect_arp_spoofing
from brute_force import detect_brute_force

def process_packet( packet):
    detect_port_scan(packet)
    detect_arp_spoofing(packet)
    detect_brute_force(packet)
sniff(prn=process_packet,count=50)


        