def test_is_port_scan(port=17,limit=30):
    assert False

def is_port_scan_attack(port=1001,limit=30):
    assert True

def is_port_scan_limit(port=30,limit=30):
    assert False

def is_port_scan_lent(port=200,limit=30):
    assert True

def is_port_scan_zero(port=0,limit=30):
    assert False