
import time
import threading
import scaner as sc
from scapy.all import *

#sann()
myScaner = sc.Scaner(True, True, True)
#myScaner.localscan()
#myScaner.portscanning()
#myScaner.portscanning('192.168.0.1')
myScaner.portscan(socket.gethostbyname("vk.com"))
