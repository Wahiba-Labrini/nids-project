import pandas as pd
from database.models import TrafficWindow
from database.database import session
from analysis.pandas_analyzing import analyzer
from analysis.pcap_to_dataframe import transfrom_to_dataframe
from scapy.all import rdpcap

packet=rdpcap("port_scan_attack.pcapng")
result=transfrom_to_dataframe(packet)
df=pd.DataFrame(result)

res=analyzer(df)


for  time,packet_sec in res["packet_per_seconde"].items():
    ports=res["unique_port_window"][time]
    print("TIME: ",time ,"| PACKET/SEC: ",packet_sec,"| PORTS: ",ports)

    row=TrafficWindow(window_start=time,packets_per_seconde=float(packet_sec),unique_ports=int(ports))

    session.add(row)

session.commit()

    