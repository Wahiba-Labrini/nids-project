def zscore(value,mean,std):
    z=(value-mean)/std
    return z

def is_anomaly(value,mean,std):
    Z=zscore(value,mean,std)
    if Z>3 :
        return True
    else:
        return False