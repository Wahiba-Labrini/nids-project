from analysis.algorithms.port_scan import is_port_scan,detect_ports
from run import load_windows

#  Testing is_port_scan()

def test_is_port_scan():
    assert   is_port_scan(17,30) is False

def is_port_scan_attack():
    assert  is_port_scan(1001,30) is True

def is_port_scan_limit():
    assert  is_port_scan(30,30) is False

def is_port_scan_lent():
    assert  is_port_scan(10,30) is True

def is_port_scan_zero(port=0,limit=30):
    assert  is_port_scan(0,30) is False

#  Testing detect_ports()

res_normal=load_windows("normal_traffic.pcapng")
res_attack=load_windows("port_scan_attack.pcapng")

def test_detect_ports_normal():
    assert detect_ports(res_normal,30) == []

def test_detect_ports_attack():
    res=detect_ports(res_attack,30) 
    print(res)
    assert res != []

   


