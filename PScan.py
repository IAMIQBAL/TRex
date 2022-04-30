import sys
import threading
from queue import Queue
import socket
from scapy.all import *
from Utility import OSdetect

class PScan:
    def __init__(self, host, q, nThreads, tOut, pRange):
        self.host = host
        self.q = q
        self.nThreads = nThreads
        self.tOut = tOut
        self.openPorts = []
        self.pRange = pRange
        socket.setdefaulttimeout(tOut)

    def scanner(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.tOut)
            sock.connect((self.host, port))
            print(f"Port {port} -> OPEN")
            self.openPorts.append(port)
            sock.close()
        except (socket.timeout, ConnectionRefusedError):
            pass

    def util(self):
        while True:
            nextPort = self.q.get()
            self.scanner(nextPort)
            self.q.task_done()

    def start(self):
        for i in range(self.nThreads):
            i = threading.Thread(target=self.util)
            i.daemon = True
            i.start()

        for x in self.pRange:
            self.q.put(x)

        self.q.join()
        print("Open Ports: ", self.host, self.openPorts)