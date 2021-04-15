import sys
import os

from secureFTP.netsim.netinterface import NetworkInterface


class Communicator:
    address = ""
    server_address = ""
    net_path = "./network/"
    net_if = None

    def __init__(self, address, net_path):
        if (net_path[-1] != '/') and (net_path[-1] != '\\'):
            net_path += '/'

        if not os.access(net_path, os.F_OK):
            print("Error: Cannot access path " + net_path)
            sys.exit(1)

        if address not in NetworkInterface.addr_space:
            print("Error: Invalid address " + address)
            sys.exit(1)

        self.address = address[0]
        self.net_path = net_path
        self.net_if = NetworkInterface(net_path, address)