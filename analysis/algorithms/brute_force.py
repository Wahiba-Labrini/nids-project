def is_brute_force(attempts,limit):
    return attempts > limit

def detect_brute_force(res,limit):
    suspicious=[]
    for window,target in res["syn_per_target"].items():
        if is_brute_force(target,limit):
            suspicious.append(window)
    return suspicious
             