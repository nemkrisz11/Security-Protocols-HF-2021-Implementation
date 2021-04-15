from secureFTP.netsim.netinterface import NetworkInterface
from secureFTP.netsim.communicator import Communicator
from cryptography.hazmat.primitives import asymmetric, ciphers, hashes, serialization


class FTPServer(Communicator):


    def __init__(self, address, net_path):
        super().__init__(address, net_path)
