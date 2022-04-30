from scapy.all import *
from scapy.layers.inet import IP, ICMP

def OSdetect(ip):
    flag = -1
    req = IP(dst=ip)/ICMP()
    res = sr1(req, timeout=3)
    print("RESPONSE: ", res)
    if res:
        if IP in res:
            ttl = res.getlayer(IP).ttl
            if ttl <= 64:
                flag = 0
            elif ttl > 64:
                flat = 1
            else:
                print("OS Detection Failed")

    return flag