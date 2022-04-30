import threading
import subprocess
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from Utility import OSdetect

class PSweep:
    def __init__(self, q, IP, nThreads):
        self.q = q
        self.count = 0
        self.IP = IP
        self.nThreads = nThreads
        self.upHosts = []
        

    def util(self):
        while True:
            nextIP = self.q.get()
            on = self.scan(nextIP)
            if on != 0:
                self.count += 1
                self.upHosts.append(nextIP)
            self.q.task_done() # Script hangs if we don't call .task_done() if we have used .join()
            
    def scan(self, nextIP):
        on = 0
        command = subprocess.Popen(['ping', '-c', '1', str(nextIP)], stderr=subprocess.PIPE, stdout=subprocess.PIPE).communicate()
        if "1 received" in command[0].decode('utf-8'):
            print(f"-> {nextIP} is ONLINE")
            online = nextIP
        else:
            print(f"-> {nextIP} is OFFLINE")
            online = 0
        return online
        

    def start(self):

        for i in range(self.nThreads):
            x = threading.Thread(target=self.util)
            x.daemon = True
            x.start()

        CIDR = str(self.IP)
        host = list(ipaddress.ip_network(CIDR).hosts())

        print(f"Starting Scan: ")
        for i in host:
            self.q.put(i)

        self.q.join()
        print("Scan Complete")
        return self.count, self.upHosts
    