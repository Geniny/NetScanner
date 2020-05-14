from scapy.all import *
import threading
import os
from socket import *
from datetime import datetime
from scapy.config import conf

class Scaner:

    hostIp = ARP().psrc
    popularPorts = [20, 21, 22, 23, 25, 42, 43, 53, 67, 69, 80, 110, 115, 123, 137, 138, 139, 143, 161, 179, 443, 445, 514, 515, 993]

    def __init__(self, isPortScanning, isWatching, isDebugging):
        self.isPortScanning = isPortScanning
        self.isWatching = isWatching
        self.isDebugging = isDebugging

    def localscan(self):
        arping("192.168.100.1/24")
        def arpscan(ip):
            arp_request = ARP(pdst = ip)
            response = srp(Ether(dst = 'ff:ff:ff:ff:ff:ff') / arp_request, iface = conf.iface, timeout=1, verbose = False)[0]
            if response:
                print(response.summary())
            if self.isDebugging:
                print(arp_request.summary())

        for i in [1,4,6]:
            net = self.hostIp.split('.')
            ip = net[0] + "." + net[1] + "." + net[2] + "." + str(i)
            arpscan(ip)



    def ping(self, ip):
        response = srp1(IP(dst=ip) / ICMP(), timeout=3, verbose=False)
        print(conf.iface)
        resultStr = '- '
        if self.isDebugging:
            resultStr += '[ICMP]: '
        if response:
            if response[ICMP].code == 0:
                resultStr +="Host {} is on-line".format(ip)
                print(resultStr)
                return response[ICMP].code
        resultStr += "Host {} is off-line".format(ip)
        print(resultStr)
        return None

    def isAlive(self, ip):
        response = self.ping(ip)
        if response == 0:
            return True
        return False

    def portscan(self, ip):
        if self.isAlive(ip) == False:
            return

        def syn(port):
            response = sr1(IP(dst=ip) / TCP(sport = RandShort(), dport=port, flags="S"), verbose=True, timeout=2)

            if response:
                response.show()
                if response[TCP].flags & 0x02 and response[TCP].flags & 0x10:
                    return port
            return

        def ack(port):
            response = sr1(IP(dst=ip) / TCP(dport=port, flags="A"), verbose=False, timeout=0.2)

            if response:
                if response[TCP].flags & 0x04 :
                    return port
            return

        def xmas(port):
            response = sr1(IP(dst=ip) / TCP(dport=port, flags="FPU"), verbose=False, timeout=0.2)

            if response:
                if response[TCP].flags & 0x04 and response[TCP].flags & 0x10:
                    return port
            return
        print("syn")
        open_ports = []
        for i in [80,443]: #self.popularPorts:
            port = syn(i)
            if port is not None:
                open_ports.append(port)

        print(open_ports)

        '''
        open_ports = []
        for i in self.popularPorts:
            port = xmas(i)
            if port is not None:
                open_ports.append(port)
        print("xmas")
        print(open_ports)

        filtred_ports = []
        for i in self.popularPorts:
            port = ack(i)
            if port is not None:
                filtred_ports.append(port)
        print("filtred")
        print(filtred_ports)
        '''

