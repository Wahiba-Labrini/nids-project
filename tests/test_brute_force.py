from analysis.algorithms.brute_force import is_brute_force,detect_brute_force
from run import load_windows

#  Testing is_brute_force()

def test_is_brute_force():
    assert is_brute_force(6,20)== False

def test_is_brute_force_limit():
    assert  is_brute_force(20,20)== False

def test_is_brute_force_valid():
    assert  is_brute_force(21,20)== True

def test_is_brute_force_zero():
    assert  is_brute_force(0,20)== False

#  Testing detect_brute_force()

res_normal=load_windows("normal_traffic.pcapng")
res_attack=load_windows("port_scan_attack.pcapng")

def test_no_detect_brute_force():
    assert detect_brute_force(res_normal,20) == []
    assert detect_brute_force(res_attack,20) == []

def test_detect_brute_force():
    fake_res={"syn_per_target":{"w1":6,"w2":25}}
    assert detect_brute_force(fake_res,20)== ['w2']

 






