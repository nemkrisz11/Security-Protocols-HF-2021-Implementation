from secureFTP.netsim.communicator import Communicator
from cryptography.hazmat.primitives import asymmetric, ciphers, hashes, serialization
import os
import sys
import getopt


class ServerCaller(type):
    def __call__(cls, *args, **kwargs):
        """ Called when FTPServer constructor is called """
        obj = type.__call__(cls, *args, **kwargs)
        obj.serve()
        return obj


class FTPServer(Communicator, metaclass=ServerCaller):

    active_sessions = {}

    def __init__(self, address, net_path):
        super().__init__(address, net_path)

        # Generate server long-term keypair

        # Create server certificate

        # Start main loop

    def serve(self):
        while True:
            status, received_msg = self.net_if.receive_msg(blocking=True)

            print("Server got message")
            print(status)
            print(received_msg)


if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], shortopts='hp:a:', longopts=['help', 'path=', 'addr='])
    except getopt.GetoptError:
        print("Usage: python server.py -p <network path> -a <address>")
        sys.exit(1)

    net_path = "../network/"
    address = "A"

    for opt, arg in opts:
        if opt == '-h' or opt == '--help':
            print("Usage: python server.py -p <network path> -a <address>")
            sys.exit(0)
        elif opt == '-p' or opt == '--path':
            net_path = arg
        elif opt == '-a' or opt == '--addr':
            address = arg

    server = FTPServer(address, net_path)
