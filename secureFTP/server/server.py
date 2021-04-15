from secureFTP.netsim.communicator import Communicator
from cryptography.hazmat.primitives import asymmetric, ciphers, hashes, serialization
import os


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
    server = FTPServer("A", "../network/")
