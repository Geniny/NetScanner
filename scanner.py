from scapy.all import *
import threading
import os
from socket import *
from datetime import datetime
import time
from scapy.config import conf
import prettytable

class Scaner:

    hostIp = None
    hostMac = None
    popularPorts = [20, 21, 22, 23, 25, 42, 43, 53, 67, 69, 80, 110, 115, 123, 137, 138, 139, 143, 161, 179, 443, 445, 514, 515, 993]
    allPorts = [i for i in range(1,65534)]

    def __init__(self,isWatching, isLogging):
        local_arp_request = ARP()
        self.isWatching = isWatching
        self.isLogging = isLogging
        self.hostIp = local_arp_request.psrc
        self.hostMac = local_arp_request.hwsrc

    def synscan(self, ip, port):
        scanPacket = IP(dst=ip) / TCP(sport=RandShort(), dport=port, flags="S")
        response = sr1( scanPacket, verbose=False, timeout=0.2)
        if self.isLogging:
            print("LOG: ", scanPacket.summary())
        if response:
            if self.isLogging:
                print("LOG: ", response.summary())
            if response[TCP].flags & 0x02 and response[TCP].flags & 0x10:
                return port
        return

    def arpscan(self, ip):
        start_timer = time.time()
        netPrefix = self.get_netPrefix(ip)
        arp_request = ARP(pdst=netPrefix + "1/24")
        positive_response, negative_response = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / arp_request, iface=conf.iface,
                                                       timeout=1, verbose=False)
        end_timer = time.time()

        if self.isLogging:
            for element in positive_response:
                print("LOG: {} {}".format(element[0].summary(), element[1].summary()))
            for element in negative_response:
                print("LOG: {}".format(element.summary()))

        if positive_response:
            table = prettytable.PrettyTable(["IP-adress","MAC-adress"])
            table.align["IP-adress"] = "l"
            for element in positive_response:
                table.add_row([element[1].psrc, element[1].hwsrc])

            print(table.get_string(title = "Local network devices"))

        if self.isWatching:
            print("WATCH: execution time is {} sec".format(end_timer - start_timer))

    def stat(self):
        print("Host ip: ",self.hostIp)
        print("Host mac: ", self.hostMac)
        print("Host interface name: ", conf.iface)
        open_ports = []
        for i in self.popularPorts:
            port = self.synscan(self.hostIp, i)
            if port is not None:
                open_ports.append(port)
        print("Open ports: ", end ='')
        if len(open_ports) == 0:
            print("no open ports")
        else:
            for i in open_ports:
                print("{} ".format(i))
            print()

    def get_netPrefix(self, ip):
        splittedIp = ip.split('.')
        return splittedIp[0] + '.' + splittedIp[1] + '.' + splittedIp[2] + '.'

    def icmpping(self, ip):
        start_timer = time.time()
        pingPacket = IP(dst=ip) / ICMP()
        response = sr1(pingPacket, timeout=3, verbose=False)
        end_timer = time.time()
        if self.isLogging:
            print("LOG: ", pingPacket.summary())
        if self.isWatching:
            print("WATCH: execution time is {} sec".format(end_timer - start_timer))
        if response:
            if response[ICMP].code == 0:
                return response[ICMP].code
        return None

    def tcpping(self, ip):
        start_timer = time.time()
        pingPacket = IP(dst = ip) / TCP(dport = 80, flags = "S")
        response = sr1(pingPacket, timeout = 0.3, retry = 1, verbose = False)
        end_timer = time.time()
        if self.isLogging:
            print("LOG: ", pingPacket.summary())
            if response: print("LOG: ", response.summary())
        if self.isWatching:
            print("WATCH: execution time is {} sec".format(end_timer - start_timer))
        if response:
            if response[TCP].flags & 0x02 and response[TCP].flags & 0x10:
                return 0
        return None

    def ackscan(self, ip, port):
        scanPacket = IP(dst=ip) / TCP(dport=port, flags="A")
        response = sr1(scanPacket, verbose=False, timeout=0.5, retry = 1)
        if self.isLogging:
            print("LOG: ", scanPacket.summary())
        if response:
            if self.isLogging:
                print("LOG: ", response.summary())
            if response[TCP].flags & 0x04:
                return port
        return

    def xmasscan(self, ip, port):
        scanPacket = IP(dst=ip) / TCP(dport=port, flags="FPU")
        response = sr1(scanPacket, verbose=False, timeout=0.5, retry = 1)
        if self.isLogging:
            print("LOG: ", scanPacket.summary())
        if response:
            if self.isLogging:
                print("LOG: ", response.summary())
            if response[TCP].flags & 0x04 and response[TCP].flags & 0x10:
                return port
        return

    def nullscan(self, ip, port):
        scanPacket = IP(dst=ip) / TCP(dport=port, flags=None)
        response = sr1(scanPacket, verbose=False, timeout=0.5, retry=1)
        if self.isLogging:
            print("LOG: ", scanPacket.summary())
        if response:
            if self.isLogging:
                print("LOG: ", response.summary())
            if response[TCP].flags & 0x04:
                return
            else:
                return  port
        return

