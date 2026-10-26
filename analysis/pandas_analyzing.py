from analysis.pcap_to_dataframe import transfrom_to_dataframe
from scapy.all import rdpcap
import pandas as pd

def most_common(series):
    if series.empty:
        return None
    else:
        return series.mode().iloc[0]
        


def analyzer(df):
    results={}

    results["src_counts"] = df['src_ip'].value_counts()

    results["dst_counts"] = df['dst_ip'].value_counts()

    results["port_counts"]  = df['port'].value_counts()

    results["grouped"] = df.groupby(['src_ip','dst_ip']).size()

    df['timestamp']=pd.to_datetime(df['timestamp'],unit='s')

    df = df.set_index('timestamp')

    results["seconde"] = df.resample('5s').size()
    results["packet_per_seconde"] = results["seconde"] / 5
    results["unique_port_window"] = df.resample('5s')["port"].nunique()
    results["src_ip_window"] = df.resample('5s')["src_ip"].agg(most_common)
    results["dst_ip_window"] = df.resample('5s')['dst_ip'].agg(most_common)

    return results


packet=rdpcap("port_scan_attack.pcapng")
result=transfrom_to_dataframe(packet)
df=pd.DataFrame(result)
res=analyzer(df)
print(res)
print(res["packet_per_seconde"])
print(res["unique_port_window"])
"""
print("--GROUPED-BY-IP-PAIR--")
print(res["grouped"])
...
"""
