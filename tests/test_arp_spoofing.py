from analysis.algorithms.arp_spoofing import extract_arp_spoofing,build_baseline,is_arp_spoofing,detect_arp_spoofing
import pandas as pd

# Testing extract_arp_spoofing()

def test_extract_arp_spoofing_normal():
    assert len(extract_arp_spoofing("normal_traffic.pcapng")) == 60

def test_extract_arp_spoofing_attack():
    assert len(extract_arp_spoofing("port_scan_attack.pcapng")) == 0

# Testing is_arp_spoofing()

baseline={"192.168.1.1":"aa:aa:aa:aa:aa:aa"}
def test_is_arp_spoofing_no_exist_ip():
    assert is_arp_spoofing("192.155.1.2","aa:aa:aa:aa:aa:aa",baseline) == False

def test_is_arp_spoofing_exist_ip_mac():
    assert is_arp_spoofing("192.168.1.1","aa:aa:aa:aa:aa:aa",baseline) == False

def test_is_arp_spoofing_diffr_ip_mac():
    assert is_arp_spoofing("192.168.1.1","bb:bb:bb:bb:bb:bb",baseline) == True

# Testing detect_arp_spoofing()

res=extract_arp_spoofing("port_scan_attack.pcapng")
def test_no_detect_arp_spoofing():
    assert len(detect_arp_spoofing(res,build_baseline(res)))== 0

df=pd.DataFrame({'ip':["192.155.1.2","192.168.1.1","192.168.1.1"],
                'mac':["aa:aa:aa:aa:aa:aa","aa:aa:aa:aa:aa:aa","bb:bb:bb:bb:bb:bb"],
                'time':[1,2,3]})

def test_detect_arp_spoofing():
    assert len(detect_arp_spoofing(df,baseline))== 1
    assert detect_arp_spoofing(df,baseline)== [(3,"192.168.1.1","bb:bb:bb:bb:bb:bb")]
        
    



   


