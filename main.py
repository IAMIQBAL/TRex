from PSweep import PSweep
from Utility import OSdetect
from Utility import parser
from Utility import banner
from PScan import PScan
import queue
import sys

if __name__ == "__main__":
    mode, nw = parser(sys.argv)

    q = queue.Queue()
    START = 0
    END = 65535
    THREADS = 100
    TIMEOUT = 0.1

    print("NW: ", nw)

    if mode == 0 or mode == 1:
        START = int(input("Specify port range START: "))
        END = int(input("Specify port range END: "))
        THREADS = int(input("Enter number of THREADS: "))

        pSweep = PSweep(q, nw, THREADS)
        hosts, upHosts = pSweep.start()
        print(f"Hosts Up: {hosts}")
        print(f"Hosts: {upHosts}")

        q = queue.Queue()

        for i in upHosts:
            ports = [i for i in range(START, END)]
            scan = PScan(str(i), q, THREADS, TIMEOUT, ports)
            scan.start()

        if mode == 1:
            # OS Fingerprinting when host is UP
            for i in upHosts:
                res = OSdetect(str(i))
                if res == 0:
                    print("Linux")
                elif res == 1:
                    print("Windows")
    elif mode == 2:
        THREADS = int(input("Enter number of THREADS: "))

        pSweep = PSweep(q, nw, THREADS)
        hosts, upHosts = pSweep.start()
        print(f"Hosts Up: {hosts}")
        print(f"Hosts: {upHosts}")
    elif mode == 3:
        res = OSdetect(str(nw))
        if res == 0:
            print("Linux")
        elif res == 1:
            print("Windows")
    else:
        banner(argv)
