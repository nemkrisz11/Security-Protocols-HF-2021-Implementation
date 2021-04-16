from secureFTP.netsim.communicator import Communicator
from secureFTP.protocol.header import *
from cryptography.hazmat.primitives import ciphers, hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
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
    active_sessions = {}

    def __init__(self, address, net_path):
        super().__init__(address, net_path)

        # Generate server long-term keypair
        self.lt_server_private_key = ec.generate_private_key(ec.SECP521R1())

        # Save public key

        # Serialize, encrypt and save private key

        # Create server certificate

    def init_session(self, msg_src, received_msg):
        # Split message
        header = received_msg[0:16]  # 16 bytes of header
        if header != init_header:
            print("Header mismatch detected!")
            # TODO : error handling

        client_proof = received_msg[16:48]  # 32 bytes of client proof
        ecdh_client_public_key = serialization.load_der_public_key(received_msg[48:])

        # Generate ephemeral ECDH keypair
        ecdh_server_private_key = ec.generate_private_key(ec.SECP521R1())
        ecdh_server_public_key = ecdh_server_private_key.public_key()

        # Choose a non-colliding SessionID for the session
        while True:
            session_id = secrets.token_hex(8)
            if not any(session_id in s["SessionID"] for s in self.active_sessions.values()):
                break

        # Construct session key
        shared_secret = ecdh_server_private_key.exchange(
            ec.ECDH(),
            ecdh_client_public_key
        )

        session_key = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=None,
            info=b"session_key"
        ).derive(shared_secret)

        # Save session parameters
        self.active_sessions[received_msg] = {
            "ConnStatus": 0,
            "SessionID": session_id,
            "DHPrivServer": ecdh_server_private_key,
            "DHPubServer": ecdh_server_public_key,
            "DHPubClient": ecdh_client_public_key,
            "SessionKey": session_key
        }

        # Send server auth message
        # Sign(Header | SessionID | Cert | Proof | ecdh_server_public_key | (HMAC?))

    def authenticate_user(self, msg_src, msg):
        pass

    def handle_command(self, msg_src, msg):
        pass

    def serve(self):
        while True:
            status, received_msg = self.net_if.receive_msg(blocking=True)

            print("Server got message")  # Debug
            print(status)  # Debug
            print(received_msg)  # Debug

            msg_src = received_msg[0]
            msg = received_msg[1:]

            if msg_src in self.active_sessions.keys():
                # Existing connection, look up parameters
                session = self.active_sessions[msg_src]

                if session["ConnStatus"] == 0:
                    # Attempt user authentication
                    self.authenticate_user(msg_src, msg)

                elif session["ConnStatus"] == 1:
                    # Authenticated user, try to parse command
                    self.handle_command(msg_src, msg)

                continue

            else:
                # New session init
                self.init_session(msg_src, msg)

                continue


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
