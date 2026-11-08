from scapy.all import rdpcap,ARP
import pandas as pd

def extract_arp_spoofing(path):
    packets=rdpcap(path)
    times=[]
    ips=[]
    macs=[]
    for packet in packets:
        if  packet.haslayer(ARP):
            times.append(float(packet.time))
            ips.append(packet[ARP].psrc)
            macs.append(packet[ARP].hwsrc)
    df=pd.DataFrame({'time':times,'ip':ips,'mac':macs})
    #print(len(df))
    return df


def build_baseline(df):
    baseline={}
    for ip,mac in zip(df['ip'],df['mac']):
        baseline[ip] = mac
    return baseline

def is_arp_spoofing(ip,mac,baseline):
    if ip not in  baseline:
        return False
    if baseline[ip] == mac:
        return False
    else:
        return True

def detect_arp_spoofing(df,baseline):
    detects=[]
    for time ,ip ,mac in zip(df['time'],df['ip'],df['mac']):
        if is_arp_spoofing(ip,mac,baseline):
            detects.append((time,ip,mac))
    return detects



    

