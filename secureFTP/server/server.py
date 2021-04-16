from secureFTP.netsim.communicator import Communicator
from secureFTP.protocol.header import *
from cryptography.hazmat.primitives import ciphers, hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import os
import sys
import getopt
import secrets


class ServerCaller(type):
    def __call__(cls, *args, **kwargs):
        """ Called when FTPServer constructor is called """
        obj = type.__call__(cls, *args, **kwargs)
        obj.serve()
        return obj


class FTPServer(Communicator, metaclass=ServerCaller):

    lt_server_private_key = None
    lt_server_public_key = None

    """
    dict of dicts, the keys are network identifiers
    value format:
    { ConnStatus : 0 - Unauthenticated, 1 - Authenticated
      SessionID :
      DHPriv :
      DHPub :
      SessionKey :
      ... ?
    }
    """
    active_sessions = {}

    def __init__(self, address, net_path):
        super().__init__(address, net_path)

        # Generate server long-term keypair
        self.lt_server_private_key = ec.generate_private_key(ec.SECP521R1())

        # Save public key

        # Serialize, encrypt and save private key

        # Create server certificate


    def serve(self):
        while True:
            status, received_msg = self.net_if.receive_msg(blocking=True)

            print("Server got message")  # Debug
            print(status)  # Debug
            print(received_msg)  # Debug

            msg_src = received_msg[0]

            if msg_src in self.active_sessions.keys():
                # Existing connection, look up sessionID
                session = self.active_sessions[msg_src]
                session_id = session["SessionID"]

                pass  # TODO

            else:
                # New session init
                # Split message
                header = msg_src[1:17]  # 16 bytes of header
                if header != init_header:
                    print("Header mismatch detected!")
                    # TODO : error handling

                client_proof = msg_src[17:49]  # 32 bytes of client proof
                ecdh_client_public_key = serialization.load_der_public_key(msg_src[49:])

                # Generate ephemeral ECDH keypair
                ecdh_server_private_key = ec.generate_private_key(ec.SECP521R1())
                ecdh_server_public_key = ecdh_server_private_key.public_key()

                # Choose a non-colliding SessionID for the session
                while True:
                    session_id = secrets.token_hex(8)
                    if not any(session_id in s["sessionID"] for s in self.active_sessions.values()):
                        break

                # Construct session key


                # Save session parameters

                self.active_sessions[msg_src] = {}  # TODO


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
