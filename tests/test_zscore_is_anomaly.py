from analysis.detection import zscore,is_anomaly

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
