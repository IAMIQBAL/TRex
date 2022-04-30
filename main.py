from PSweep import PSweep
from Utility import OSdetect
from PScan import PScan
import queue

if __name__ == "__main__":
    q = queue.Queue()
    START = 0
    END = 100
    THREADS = 100
    TIMEOUT = 0.1
    pSweep = PSweep(q, '172.16.55.0/24', THREADS)
    hosts, upHosts = pSweep.start()
    print(f"Hosts Up: {hosts}")
    print(f"Hosts: {upHosts}")

    q = queue.Queue()
    for i in upHosts:
        ports = [i for i in range(START, END)]
        scan = PScan(str(i), q, THREADS, TIMEOUT, ports)
        scan.start()

    # OS Fingerprinting when host is UP
    for i in upHosts:
        res = OSdetect(str(i))
        if res == 0:
            print("Linux")
        elif res == 1:
            print("Windows")
