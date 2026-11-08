from analysis.algorithms.anomaly_detection import zscore,is_anomaly,detect_anomalies
from run import load_windows,get_baseline

def test_zscore():
    """IS THE CALCULE IS RIGHT ? """
    res=zscore(15,10,2)
    assert res == 2.5

def test_is_anomaly():
    """IS HIGH VALUE RETURN TRUE ? """    
    res=is_anomaly(100,10,2)
    assert res == True

def test_is_anomaly_invalid():
    """ CHECK INVALID TEST"""
    res=is_anomaly(11,10,2)
    assert res == False

def test_is_anomaly_negval():
    """ CHECK NEGATIVE VALUE """
    res=is_anomaly(-200,10,2)
    assert res == False

def test_is_anomaly_closval():
    """ TRESHOLD VALUE"""
    res=is_anomaly(16,10,2)
    assert res == False

def test_is_anomaly_closval():
    """ VALUE CLOSE """
    res=is_anomaly(17,10,2)
    assert res == True

def test_is_anomaly_zero():
    """ CHECK VALUE = 0 """
    res=is_anomaly(0,10,2)
    assert res == False

# Testing  detect_anomalies()

res_normal=load_windows("normal_traffic.pcapng")
mean_val,std_val=get_baseline(res_normal)
res_attack=load_windows("port_scan_attack.pcapng")

def test_detect_anomalies():
    assert detect_anomalies(res_attack,mean_val,std_val)