from scapy.all import *
from scapy.layers.inet import IP, ICMP
import getopt
import sys

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

def parser(argv):
    help_arg = ""
    network_arg = ""
    user_arg = ""
    ip_arg = ""

    # Full Network scan = 0
    # Network scan with OS detection = 1
    # Ping Sweep only = 2
    # Single ip OS detection = 3

    help_arg = banner(argv)

    try:
        opts, args = getopt.getopt(argv[1:], "i:A:p:T:", ["network"])
    except:
        print(help_arg)
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print(help_arg)
            sys.exit(2)
        elif opt in ("-i"):
            network_arg = arg
            return 0, network_arg
        elif opt in ("-A"):
            network_arg = arg
            return 1, network_arg
        elif opt in ("-p"):
            network_arg = arg
            return 2, network_arg
        elif opt in ("-T"):
            ip_arg = arg
            return 3, ip_arg

def banner(argv):
    return """Usage: {0} [OPTION...] [IP...]
    Target Specification:
    \tCan pass IP addresses, networks, etc.
    \tEx: {0} -i 192.168.0.1/24
    Complete network Scan:
    \t{0} -i <network>
    Network Scan with OS Detection:
    \tsudo {0} -A <network>
    Ping Sweep:
    \t{0} -p <network>""".format(argv[0])