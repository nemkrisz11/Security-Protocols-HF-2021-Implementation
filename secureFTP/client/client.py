from secureFTP.netsim.communicator import Communicator
from secureFTP.protocol.header import *
from cryptography.hazmat.primitives import ciphers, hashes, padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import secrets


class FTPClient(Communicator):
    server_address = None
    ecdh_client_private_key = None
    ecdh_client_public_key = None

    def __init__(self, address, server_address, net_path):
        super().__init__(address, net_path)
        self.server_address = server_address

    def init_session(self):
        # Generate ephemeral ECDH keypair
        self.ecdh_client_private_key = ec.generate_private_key(ec.SECP521R1())
        self.ecdh_client_public_key = self.ecdh_client_private_key.public_key()

        # Generate client proof
        client_random = secrets.token_bytes(32)

        # Send init message
        msg = bytes(self.address, 'utf-8') + init_header + client_random + \
              self.ecdh_client_public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

        self.net_if.send_msg(self.server_address, msg)

        # Wait for server response
        status, msg_server_init = self.net_if.receive_msg(blocking=True)

        print(msg_server_init)

        # Construct session key

        # Validate signature

        # Generate nonce

        # Generate client sequence number

        # Get Username and Password from user

        # Send client authentication message

        # Wait for server response

    def close_session(self):
        pass
