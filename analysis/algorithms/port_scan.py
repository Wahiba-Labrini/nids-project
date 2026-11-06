def is_port_scan(port,limit):
    return port > limit

def detect_ports(res,limit):
    ports=[]
    for time,port in res["unique_port_window"].items():
        if is_port_scan(port,limit):
            ports.append(time)
    return ports