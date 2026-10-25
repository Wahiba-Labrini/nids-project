import pandas as pd
from database.models import TrafficWindow
from database.database import session
from analysis.pandas_analyzing import analyzer
from analysis.pcap_to_dataframe import transfrom_to_dataframe
from scapy.all import rdpcap
import numpy as np
from analysis.detection import zscore, is_anomaly

def load_windows(path):
    packet=rdpcap(path)
    result=transfrom_to_dataframe(packet)
    df=pd.DataFrame(result)
    res=analyzer(df)
    return res



res=load_windows("normal_traffic.pcapng")
for  time,packet_sec in res["packet_per_seconde"].items():
    pps_list=[]
    ports=res["unique_port_window"][time]
    pps_list.append(packet_sec)
    print("TIME: ",time ,"| PACKET/SEC: ",packet_sec,"| PORTS: ",ports)

    #row=TrafficWindow(window_start=time,packets_per_seconde=float(packet_sec),unique_ports=int(ports))

mean_val=round(np.mean(pps_list),2)
std_val=round(np.std(pps_list),2)
#print(mean_val,std_val)
#z=(401.2-mean_val)/std_val
#print(round(z,2))
#print(round(zscore(401.2,mean_val,std_val),2))
#   print(is_anomaly(mean_val,mean_val,std_val))
    #session.add(row)

#session.commit()

res_attack=load_windows("port_scan_attack.pcapng")
for time,value in res_attack["packet_per_seconde"].items():
    result=is_anomaly(value,mean_val,std_val)
    print("TIME:",time, "VALUE :",value, "RESULT:",result)


    