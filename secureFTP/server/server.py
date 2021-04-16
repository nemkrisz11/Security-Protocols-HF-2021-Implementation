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
import pymongo


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
    server_certificate = None

    DATABASE_NAME = 'secureFTP'
    COLLECTION_NAME = 'Users'
    MONGODB_ADDRESS = 'mongodb://localhost:27017/'

    def __init__(self, address, net_path):
        super().__init__(address, net_path)

        # Generate server long-term keypair
        self.lt_server_private_key = ec.generate_private_key(ec.SECP521R1())

        # Save public key

        # Serialize, encrypt and save private key
        ser_lt_server_private_key = self.lt_server_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                b'testpassword') #  TODO: proper password
            )
        #  TODO: write encrypted private key to file

        # Create server certificate

    async def init_session(self, msg_src, received_msg):
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
        self.active_sessions[msg_src] = {
            "ConnStatus": 0,
            "SessionID": session_id,
            "DHPrivServer": ecdh_server_private_key,
            "DHPubServer": ecdh_server_public_key,
            "DHPubClient": ecdh_client_public_key,
            "SessionKey": session_key
        }

        # Pad the SessionID
        padder = padding.ANSIX923(256).padder()
        padded_session_id = padder.update(session_id) + padder.finalize()

        # Construct the message
        # Msg = Address | Header | Padded SessionID | CertLen | Cert | Proof | ServerPublicKey | Sign(Msg)
        msg = self.address + init_header + padded_session_id + bytes(len(self.server_certificate)) + \
                self.server_certificate + client_proof + \
                ecdh_server_public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

        # Sign the message
        signature = self.lt_server_private_key.sign(msg, ec.ECDSA(hashes.SHA512()))
        msg += signature

        # Send server auth message
        self.net_if.send_msg(msg_src, msg)

    async def authenticate_user(self, msg_src, msg):
        # msg NONCE | EKs(SessionID | UNlen | Username | PWlen | Password | Seqclient) | MAC

        client = pymongo.MongoClient(self.MONGODB_ADDRESS)

        db = client[self.DATABASE_NAME]
        collection = db[self.COLLECTION_NAME]

        query = {"UserName": "test1"}
        cursor = collection.find(query)
        doc = next(cursor, None)
        if doc:
            # check the password
            # doc["Password"]
            pass

    # Do your thing



    async def handle_command(self, msg_src, msg):
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
