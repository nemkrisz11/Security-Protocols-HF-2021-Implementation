from secureFTP.netsim.communicator import Communicator
from secureFTP.protocol.header import *
from secureFTP.server.certification_authority import CertificationAuthority
from cryptography import x509
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHash
from datetime import datetime, timedelta
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

        # TODO: Attempt to load existing long-term keypair and certificate
        # if ...

        # else ...
        # Generate server long-term keypair
        self.lt_server_private_key = ec.generate_private_key(ec.SECP521R1())
        self.lt_server_public_key = self.lt_server_private_key.public_key()

        # TODO: Save public key

        # Serialize, encrypt and save private key
        ser_lt_server_private_key = self.lt_server_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                b'testpassword')  # TODO: proper password
        )
        #  TODO: write encrypted private key to file

        # Create server certificate
        certification_authority = CertificationAuthority()

        csr_builder = x509.CertificateSigningRequestBuilder()
        csr_builder = csr_builder.subject_name(x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u'SecureFTP Server')
        ]))
        csr_builder = csr_builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        csr_builder = csr_builder.sign(
            self.lt_server_private_key, hashes.SHA512()
        )

        csr_pem = csr_builder.public_bytes(serialization.Encoding.PEM)

        self.server_certificate = certification_authority.request_certificate_signing(csr_pem)

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
            session_id = secrets.token_bytes(8)
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
        padder = padding.ANSIX923(128).padder()
        padded_session_id = padder.update(session_id) + padder.finalize()

        # Construct the message
        # Msg = Address | Header | Padded SessionID | CertLen | Cert | Proof | ServerPublicKey | Sign(Msg)
        msg = bytes(self.address, 'utf-8') + init_header + padded_session_id + \
              len(self.server_certificate).to_bytes(2, 'big') + self.server_certificate + client_proof + \
              ecdh_server_public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

        # Sign the message
        signature = self.lt_server_private_key.sign(msg, ec.ECDSA(hashes.SHA512()))
        msg += signature

        # Send server auth message
        self.net_if.send_msg(str(msg_src), msg)

    async def authenticate_user(self, msg_src, msg):
        session = self.active_sessions[msg_src]

        auth_msg = self.unpack_auth_message(msg, session["SessionKey"])

        if session['SessionID'] != auth_msg['SessionID']:
            # do some shit
            # TODO: error msg
            print('SessionID mismatch')

        client = pymongo.MongoClient(self.MONGODB_ADDRESS)

        db = client[self.DATABASE_NAME]
        collection = db[self.COLLECTION_NAME]

        user_name = auth_msg['UserName']
        query = {'UserName': user_name}
        doc = collection.find_one(query)
        if doc:
            if doc['LockTime'] > datetime.now():
                # auth locked msg
                # TODO: error msg
                print('Authentication locked for user')

            password_hash = doc['Password']
            password = auth_msg['Password']
            ph = PasswordHasher()

            try:
                # Verify password, raises exception if wrong.
                ph.verify(password_hash, password)

                print(f'{user_name} successfully authenticated ')
                session['ConnStatus'] = 1
                session['SequenceClient'] = auth_msg['SequenceNumber']

                server_sequence_bytes = secrets.token_bytes(8) + bytes(8)
                session['SequenceServer'] = int.from_bytes(server_sequence_bytes, 'big')

                # TODO: response msg

            except VerifyMismatchError:
                # pass-hash mismatch
                if doc['AuthAttempts'] == 4:
                    update = {'$set': {'AuthAttempts': 0, 'LockTime': datetime.now() + timedelta(minutes=10)}}
                    collection.update_one(query, update)
                else:
                    update = {'$set': {'AuthAttempts': doc['AuthAttempts'] + 1}}
                    collection.update_one(query, update)
                # TODO: error msg
                print('Authentication failed')
            except VerificationError:
                # fail for other reason
                if doc['AuthAttempts'] == 4:
                    update = {'$set': {'AuthAttempts': 0, 'LockTime': datetime.now() + timedelta(minutes=10)}}
                    collection.update_one(query, update)
                else:
                    update = {'$set': {'AuthAttempts': doc['AuthAttempts'] + 1}}
                    collection.update_one(query, update)
                # TODO: error msg
                print('Authentication failed')
            except InvalidHash:
                # invalid hash
                if doc['AuthAttempts'] == 4:
                    update = {'$set': {'AuthAttempts': 0, 'LockTime': datetime.now() + timedelta(minutes=10)}}
                    collection.update_one(query, update)
                else:
                    update = {'$set': {'AuthAttempts': doc['AuthAttempts'] + 1}}
                    collection.update_one(query, update)
                # TODO: error msg
                print('Authentication failed')
        else:
            # TODO: error msg
            print('User not found')

    def unpack_auth_message(self, msg, session_key):
        # msg NONCE | EKs(SessionID | UNlen | Username | PWlen | Password | Seqclient) | MAC

        nonce = msg[0:16]
        encrypted_payload_with_tag = msg[16:]

        aesgcm = AESGCM(session_key)
        payload = aesgcm.decrypt(nonce, encrypted_payload_with_tag, None)

        session_id = payload[0:8]
        user_name_len = int.from_bytes([payload[9]], 'big')
        user_name = payload[9:9 + user_name_len].decode('utf-8')
        password_len = int.from_bytes([payload[9 + user_name_len]], 'big')
        password = payload[-(password_len + 16):-16].decode('utf-8')
        sqn_num = payload[-16:]

        return {
            "Nonce": nonce,
            "SessionID": session_id,
            "UserName": user_name,
            "Password": password,
            "SequenceNumber": sqn_num
        }

    # Do your thing

    async def handle_command(self, msg_src, msg):
        pass

    def serve(self):
        while True:
            status, received_msg = self.net_if.receive_msg(blocking=True)

            print("Server got message")  # Debug
            print(status)  # Debug
            print(received_msg)  # Debug

            msg_src = chr(received_msg[0])
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
