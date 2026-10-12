from pcap_to_dataframe import transfrom_to_dataframe
from scapy.all import rdpcap
import pandas as pd

packet=rdpcap("port_scan_attack.pcapng")
result=transfrom_to_dataframe(packet)
df=pd.DataFrame(result)
print(df['src_ip'].value_counts())
print("*"*50)
print(df['dst_ip'].value_counts())
print("*"*50)
print(df['port'].value_counts())
print("*"*50)
grouped=df.groupby(['src_ip','dst_ip']).size()
print(grouped)
df['timestamp']=pd.to_datetime(df['timestamp'],unit='s')
print("-"*50)
df = df.set_index('timestamp')
seconde=df.resample('5s').size()
print(seconde)