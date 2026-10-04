from pcap_to_dataframe import transfrom_to_dataframe
from scapy.all import rdpcap
import json

packets=rdpcap("port_scan_attack.pcapng")
result=transfrom_to_dataframe(packets)
print(json.dumps(result,indent=4))