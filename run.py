import pandas as pd
from database.models import TrafficWindow
from database.database import session
from analysis.pandas_analyzing import analyzer
from analysis.pcap_to_dataframe import transfrom_to_dataframe
from scapy.all import rdpcap
import numpy as np
from analysis.detection import  zscore,is_anomaly,is_port_scan


def load_windows(path):
    packet=rdpcap(path)
    result=transfrom_to_dataframe(packet)
    df=pd.DataFrame(result)
    res=analyzer(df)
    return res


def get_baseline(res):
    mean_val=round(np.mean(res["packet_per_seconde"]),2)
    std_val=round(np.std(res["packet_per_seconde"]),2)
    return mean_val,std_val

def get_baseline_db(session):
    rows=session.query(TrafficWindow).filter_by(label='normal').all()
    res=[]
    for row in rows:
        res.append(row.packets_per_seconde)
    mean_val=round(np.mean(res),2)
    std_val=round(np.std(res),2)
    return mean_val,std_val
    

    
     

def detect(res,mean_val,std_val):
    anomalies=[]
    for time,packet_sec in res["packet_per_seconde"].items():
            if is_anomaly(packet_sec,mean_val,std_val):
                anomalies.append(time)
    return anomalies
    
    


def save_windows(res,label):
    for  time,packet_sec in res["packet_per_seconde"].items():
        ports=res["unique_port_window"][time]
        src=res["src_ip_window"][time]
        if pd.isna(src):
            src=None

        dst=res["dst_ip_window"][time]
        if pd.isna(dst):
                dst=None

        row = TrafficWindow(src_ip=src,dst_ip=dst,window_start=time,packets_per_seconde=float(packet_sec),unique_ports=int(ports),label=label)

        session.add(row)
        query_nor =session.query(TrafficWindow).filter_by(label='normal').all()
    session.commit()

    
def detect_ports(res,limit):
    ports=[]
    for time,port in res["unique_port_window"].items():
        if is_port_scan(port,limit):
            ports.append(time)
    return ports


     
res_normal=load_windows("normal_traffic.pcapng")
mean_val,std_val=get_baseline(res_normal)

res_attack=load_windows("port_scan_attack.pcapng")
print(detect(res_attack,mean_val,std_val))

save_windows(res_normal,"normal")
save_windows(res_attack,"attack")

print("----------------------------------------")
print(detect_ports(res_normal,30))
print(detect_ports(res_attack,30))


#print(res_normal["unique_port_window"])

