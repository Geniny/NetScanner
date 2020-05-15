import time
import scanner as sc
from scapy.all import *
from service import *
import argparse

def get_options():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p','--ports', dest='ports', help='Port(s) range')
    parser.add_argument('-r', dest='range', help='IP range')
    parser.add_argument('-l','--log', dest='log', help='Enable/disable logging', type=bool, default=False)
    parser.add_argument('-w', dest='watch', help='Enable/disable watching',type = bool, default=False)
    parser.add_argument('-lB', dest='lb', help='Local network browse',type=bool, default=False)
    options = parser.parse_args()
    return options

def main():
    options = get_options()
    scanningPorts = None
    scanningIp = None
    isLogging = None
    isWatching = None

    if options.log == True:
        isLogging = True
    else:
        isLogging = False

    if options.watch == True:
        isWatching = True
    else:
        isWatching = False

    print("\nDeveloped by Dmitriy Horbachev")
    print("Logging is ", 'enabeled' if isLogging else 'disabeled')
    print("Watching is ", 'enabeled' if isWatching else 'disabeled', end='\n\n')

    if options.ports:
        if str(options.ports).__contains__('-'):
            scanningPorts = [i for i in range(int(options.ports.split('-')[0]), int(options.ports.split('-')[1]) + 1)]
        elif str(options.ports).__contains__(','):
            scanningPorts = [int(i) for i in options.ports.split(',')]
        else:
            try:
                scanningPorts = [int(options.ports)]
            except:
                print("Exception")
                scanningPorts = None
    if options.range:
        try:
            scanningIp = socket.gethostbyname(options.range)
            print("Scanning {}".format(options.range))
        except:
            print("Host {} doesn't exists, start scannig localhost".format(options.range))
            scanningIp = socket.gethostbyname("localhost")
    else:
        print("Scanning localhost")
        scanningIp = socket.gethostbyname("localhost")




    myScaner = sc.Scaner(isWatching, isLogging)
    myService = Service(myScaner, scanningIp, scanningPorts)

    if options.lb == True:
        myService.hoststat()
        myService.localbrowse()
        return

    myService.fullscan()

    print()

if __name__ == '__main__':
    main()