def zscore(value,mean,std):
    z=(value-mean)/std
    return z

def is_anomaly(value,mean,std):
    Z=zscore(value,mean,std)
    return Z>3 

def detect_anomalies(res,mean_val,std_val):
    anomalies=[]
    for time,packet_sec in res["packet_per_seconde"].items():
            if is_anomaly(packet_sec,mean_val,std_val):
                anomalies.append(time)
    return anomalies
