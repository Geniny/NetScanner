class Service:

    def __init__(self, scanner, scanningIp, scanningPorts):
        self.scanner = scanner
        self.scannigIp = scanningIp
        self.scanningPorts = scanningPorts if scanningPorts else self.scanner.popularPorts

    def localbrowse(self):
        print("Initiating local network browse ...")
        self.scanner.arpscan(self.scanner.hostIp)

    def hoststat(self):
        print("Initiating browse host config ...")
        self.scanner.stat()

    def ping(self):
        print("Initiating ping scan ...")
        status_code = self.scanner.icmpping(self.scannigIp)
        if status_code == 0:
            print("Host {} is on-line".format(self.scannigIp))
            return 0
        else:
            print("Host {} is off-line or blocking pings".format(self.scannigIp ))
            print("Initianing tcp ping scan ...")
            status_code = self.scanner.tcpping(self.scannigIp)
            if status_code == 0:
                print("Host {} is on-line".format(self.scannigIp))
                return 0
            else:
                print("Host {} is off-line".format(self.scannigIp))
                return 1

    def portscan(self):
        print("Initiating port scan ...")
        print("Scanning ports: ", end='')
        for i in self.scanningPorts:
            print("{}".format(i), end=' ')
        print()

        print("Initiating XMAS scan ...")
        possibly_open_ports = []
        for i in self.scanningPorts:
            port = self.scanner.xmasscan(self.scannigIp, i)
            if port is not None:
                possibly_open_ports.append(port)
        print("Possibly open ports: ", end='')
        for i in possibly_open_ports:
            print("{}".format(i), end=' ')
        print()

        print("Initiating SYN scan ...")
        open_ports = []
        for i in self.scanningPorts:
            port = self.scanner.synscan(self.scannigIp, i)
            if port is not None:
                open_ports.append(port)
        print("Open ports: ", end='')
        for i in open_ports:
            print("{}".format(i), end=' ')
        print()

        print("Initiating ACK scan ...")
        filtred_ports = []
        for i in self.scanningPorts:
            port = self.scanner.ackscan(self.scannigIp, i)
            if port is not None:
                filtred_ports.append(port)
        print("Filtred ports: ", end='')
        for i in filtred_ports:
            print("{}".format(i), end=' ')
        print()

        print("Initiating NULL scan ...")
        likely_open_ports = []
        for i in self.scanningPorts:
            port = self.scanner.ackscan(self.scannigIp, i)
            if port is not None:
                likely_open_ports.append(port)
        print("Most likely open ports: ", end='')
        for i in likely_open_ports:
            print("{}".format(i), end=' ')
        print()


    def fullscan(self):
        print("Initiating full scan ...")
        isAlive = self.ping()
        if isAlive == 0:
            self.portscan()
        else:
            return
