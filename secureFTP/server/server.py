from secureFTP.netsim.communicator import Communicator
from secureFTP.protocol.header import *
from secureFTP.protocol.commands import *
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
from pathlib import Path, PurePath
import os
import sys
import getopt
import secrets
import pymongo
import re

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
    COLLECTION_NAME = 'users'
    MONGODB_ADDRESS = 'mongodb://localhost:27017/'

    users_dir = None

    def __init__(self, address, net_path, users_dir):
        super().__init__(address, net_path)

        print("Please input the server password")
        server_password = input()

        self.users_dir = os.path.realpath(users_dir) + "\\"

        # Attempt to load existing long-term keypair and certificate
        try:
            with open("./server_private_key.pem", "rb") as private_key_file:
                self.lt_server_private_key = serialization.load_pem_private_key(
                    private_key_file.read(), password=server_password.encode('utf-8'))
            with open("./server_public_key.pem", "rb") as public_key_file:
                self.lt_server_public_key = serialization.load_pem_public_key(public_key_file.read())

        except FileNotFoundError:

            # Generate server long-term keypair
            self.lt_server_private_key = ec.generate_private_key(ec.SECP521R1())
            self.lt_server_public_key = self.lt_server_private_key.public_key()

            print("Server long term public key:")
            print(self.lt_server_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))

            with open("./server_public_key.pem", "wb") as public_key_file:
                public_key_file.write(
                    self.lt_server_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                )

            # Serialize, encrypt and save private key
            ser_lt_server_private_key = self.lt_server_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    server_password.encode('utf-8'))
            )
            with open("./server_private_key.pem", "wb") as private_key_file:
                private_key_file.write(ser_lt_server_private_key)

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

    def init_session(self, msg_src, received_msg):
        # Split message
        header = received_msg[0:16]  # 16 bytes of header
        if header != init_header:
            print("Header mismatch detected!")
            return

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

        print("Session key in server:")
        print(session_key)

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
        # Msg = Address | Header | Padded SessionID | CertLen | Cert | Proof | ServerECDHPublicKey | Sign(Msg)
        msg = init_header + padded_session_id + \
              len(self.server_certificate).to_bytes(2, 'big') + self.server_certificate + client_proof + \
              ecdh_server_public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

        print("Server sent:")
        print(msg)  # Debug

        # Sign the message
        signature = self.lt_server_private_key.sign(msg, ec.ECDSA(hashes.SHA512()))
        signed_msg = msg + signature

        self.lt_server_public_key.verify(signature, msg, ec.ECDSA(hashes.SHA512()))

        signed_msg = bytes(self.address, 'utf-8') + signed_msg

        # Send server auth message
        self.net_if.send_msg(str(msg_src), signed_msg)

    def authenticate_user(self, msg_src, msg):
        # Session data
        session = self.active_sessions[msg_src]
        session_key = session["SessionKey"]

        # Creating the cipher
        aesgcm = AESGCM(session_key)

        # Trying to unpack and decipher the received message
        auth_msg = None
        try:
            auth_msg = self.unpack_auth_message(msg, session_key)
        except:
            print(f'Message error for authentication from source: {msg_src}')
            return

        if auth_msg['Close']:
            self.command_LGT(msg_src)
            return

        user_name = auth_msg['UserName']
        session_id = auth_msg['SessionID']

        # Increment the nonce
        nonce = int.from_bytes(auth_msg['Nonce'], 'big')
        nonce += 1
        nonce = nonce.to_bytes(16, 'big')

        # Building the default error message
        resp_payload = session_id + bytes(1)
        enc_payload_with_tag = aesgcm.encrypt(nonce, resp_payload, None)
        error_msg = nonce + enc_payload_with_tag

        if session['SessionID'] != session_id:
            print(f'SessionID mismatch during authentication for user: {user_name}')

            self.net_if.send_msg(msg_src, error_msg)
            return

        # Connecting to mongoDB
        client = pymongo.MongoClient(self.MONGODB_ADDRESS)
        db = client[self.DATABASE_NAME]
        collection = db[self.COLLECTION_NAME]

        # Query user from database
        query = {'UserName': user_name}
        doc = collection.find_one(query)
        if doc:
            # check if user login locked
            if doc['LockTime'] > datetime.now():
                print(f'Authentication locked for user: {user_name}')
                # success indicator with value 2 for locked user
                resp_payload = session_id + (2).to_bytes(1, 'big')

                enc_payload_with_tag = aesgcm.encrypt(nonce, resp_payload, None)

                error_msg = nonce + enc_payload_with_tag
                self.net_if.send_msg(msg_src, error_msg)
                return

            password_hash = doc['Password']
            password = auth_msg['Password']
            ph = PasswordHasher()

            try:
                # Verify password, raises exception if wrong.
                ph.verify(password_hash, password)

                print(f'{user_name} successfully authenticated ')
                session['ConnStatus'] = 1
                session['SequenceClient'] = int.from_bytes(auth_msg['SequenceNumber'], 'big')
                session['RootDirectory'] = self.users_dir + doc['RootDirectory'] + '\\'
                session['CurrentDirectory'] = session['RootDirectory']

                # making the user directory if not exist yet
                Path(session['RootDirectory']).mkdir(parents=True, exist_ok=True)

                session['UserName'] = user_name

                # generating server side sequence number
                server_sequence_bytes = secrets.token_bytes(8) + bytes(8)
                session['SequenceServer'] = int.from_bytes(server_sequence_bytes, 'big')

                update = {'$set': {'AuthAttempts': 0}}
                collection.update_one(query, update)

                resp_payload = session_id + (1).to_bytes(1, 'big') + server_sequence_bytes
                enc_payload_with_tag = aesgcm.encrypt(nonce, resp_payload, None)
                resp_msg = nonce + enc_payload_with_tag
                self.net_if.send_msg(msg_src, resp_msg)

            except VerifyMismatchError:
                # Pass-hash mismatch
                if doc['AuthAttempts'] == 4:
                    update = {'$set': {'AuthAttempts': 0, 'LockTime': datetime.now() + timedelta(minutes=10)}}
                    collection.update_one(query, update)
                else:
                    update = {'$set': {'AuthAttempts': doc['AuthAttempts'] + 1}}
                    collection.update_one(query, update)

                self.net_if.send_msg(msg_src, error_msg)

                print(f'Authentication failed for user {user_name}, password - hash mismatch')

            except VerificationError:
                # Fail for other reason
                if doc['AuthAttempts'] == 4:
                    update = {'$set': {'AuthAttempts': 0, 'LockTime': datetime.now() + timedelta(minutes=10)}}
                    collection.update_one(query, update)
                else:
                    update = {'$set': {'AuthAttempts': doc['AuthAttempts'] + 1}}
                    collection.update_one(query, update)

                self.net_if.send_msg(msg_src, error_msg)

                print(f'Authentication failed for user {user_name}, other reason')

            except InvalidHash:
                # Invalid hash
                if doc['AuthAttempts'] == 4:
                    update = {'$set': {'AuthAttempts': 0, 'LockTime': datetime.now() + timedelta(minutes=10)}}
                    collection.update_one(query, update)
                else:
                    update = {'$set': {'AuthAttempts': doc['AuthAttempts'] + 1}}
                    collection.update_one(query, update)

                self.net_if.send_msg(msg_src, error_msg)

                print(f'Authentication failed for user {user_name}, invalid hash in DB')

        else:
            self.net_if.send_msg(msg_src, error_msg)
            print(f'User not found {user_name}')

    def handle_command(self, msg_src, msg):
        # Session data
        session = self.active_sessions[msg_src]
        session_key = session["SessionKey"]
        client_sequence = session["SequenceClient"]
        server_sequence = session["SequenceServer"]

        # Creating the cipher
        aesgcm = AESGCM(session_key)

        # Trying to unpack and decipher the received message
        try:
            command_msg = self.unpack_command_message(msg, session_key)
        except:
            print(f'Message error for command from source: {msg_src}')
            return

        session_id = command_msg['SessionID']

        # Increment the client sequence
        client_sequence += 1
        session['SequenceClient'] = client_sequence

        # Increment the nonce
        nonce = self.increment_nonce(command_msg['Nonce'])

        # Building the default error message
        resp_payload = session_id + b'\x00' + client_sequence.to_bytes(16, 'big')
        enc_payload_with_tag = aesgcm.encrypt(nonce, resp_payload, None)
        error_msg = nonce + enc_payload_with_tag

        if session['SessionID'] != session_id:
            print(f'SessionID mismatch during command execution for user: {session["UserName"]}')

            self.net_if.send_msg(msg_src, error_msg)
            return

        if server_sequence >= command_msg['SequenceNumber']:
            print(f'Invalid message sequence')

            self.net_if.send_msg(msg_src, error_msg)
        else:
            session['SequenceServer'] = command_msg['SequenceNumber']

        # Execute command

        cmd = command_msg["Cmd"]
        if cmd is Commands.MKD:
            response, response_payload = self.command_MKD(session, command_msg["Params"])
        elif cmd is Commands.RMD:
            response, response_payload = self.command_RMD(session, command_msg["Params"])
        elif cmd is Commands.GWD:
            response, response_payload = self.command_GWD(session)
        elif cmd is Commands.CWD:
            response, response_payload = self.command_CWD(session, command_msg["Params"])
        elif cmd is Commands.LST:
            response, response_payload = self.command_LST(session)
        elif cmd is Commands.UPL:
            response, response_payload = self.command_UPL(session, command_msg["Params"], command_msg["Payload"])
        elif cmd is Commands.DNL:
            response, response_payload = self.command_DNL(session, command_msg["Params"])
        elif cmd is Commands.RMF:
            response, response_payload = self.command_RMF(session, command_msg["Params"])
        elif cmd is Commands.LGT:
            response, response_payload = self.command_LGT(msg_src)
        else:
            response = b'\x00'
            response_payload = b''

        # Sending a response message
        # Creating the cipher
        aesgcm = AESGCM(session_key)

        # Building the message
        msg = session['SessionID'] + response + response_payload + session['SequenceClient'].to_bytes(16, 'big')
        enc_payload_with_tag = aesgcm.encrypt(nonce, msg, None)
        enc_msg = nonce + enc_payload_with_tag

        self.net_if.send_msg(msg_src, enc_msg)

    def increment_nonce(self, nonce):
        nonce = int.from_bytes(nonce, 'big')
        nonce += 1
        nonce = nonce.to_bytes(16, 'big')

        return nonce

    # Commands --------------------------------------------------------------------------------------------------------
    # Create new directory
    def command_MKD(self, session, params):
        folders = params.split('\\')

        valid_names = True
        for folder in folders:
            if not self.validate_folder_name(folder):
                valid_names = False
                break

        if not valid_names:
            return b'\x00', 'Invalid folder name'.encode('utf-8')

        if params != "" and params[0] == "\\":
            new_dir_path = PurePath(os.path.realpath(session['RootDirectory'] + params))
        else:
            new_dir_path = PurePath(os.path.realpath(session['CurrentDirectory'] + params))

        access_violation = False
        try:
            new_dir_path.relative_to(os.path.realpath(session['RootDirectory']))
        except ValueError:
            access_violation = True

        if not access_violation:
            Path(new_dir_path).mkdir(parents=True, exist_ok=True)
            return b'\x01', b''
        else:
            return b'\x02', b''

    def validate_folder_name(self, str):
        search = re.compile(r'[^A-Za-z0-9_\-]').search
        return not bool(search(str))

    # Remove existing directory
    def command_RMD(self, session, params):
        if params != "" and params[0] == "\\":
            remove_dir_path = PurePath(os.path.realpath(session['RootDirectory'] + params))
        else:
            remove_dir_path = PurePath(os.path.realpath(session['CurrentDirectory'] + params))

        access_violation = False
        try:
            relativ_path = remove_dir_path.relative_to(os.path.realpath(session['RootDirectory']))
            # check if the folder is the root directory
            if relativ_path == PurePath('.'):
                access_violation = True
        except ValueError:
            access_violation = True

        if not access_violation:
            if os.path.exists(remove_dir_path):
                if session['CurrentDirectory'] == os.fspath(remove_dir_path) + '\\':
                    session['CurrentDirectory'] = session['RootDirectory']
                try:
                    Path(remove_dir_path).rmdir()
                    return b'\x01', b''
                except:
                    return b'\x00', 'folder not empty'.encode('utf-8')
            else:
                return b'\x03', b''
        else:
            return b'\x02', b''

    # Print working directory
    def command_GWD(self, session):
        return b'\x01', session['CurrentDirectory'].replace(session['RootDirectory'], "\\").encode('utf-8')

    # Change working directory
    def command_CWD(self, session, params):
        if params != "" and params[0] == "\\":
            new_dir_path = PurePath(os.path.realpath(session['RootDirectory'] + params))
        else:
            new_dir_path = PurePath(os.path.realpath(session['CurrentDirectory'] + params))

        access_violation = False
        try:
            new_dir_path.relative_to(os.path.realpath(session['RootDirectory']))
        except ValueError:
            access_violation = True

        if not access_violation:
            if os.path.exists(new_dir_path):
                session['CurrentDirectory'] = os.fspath(new_dir_path) + '\\'
                return b'\x01', session['CurrentDirectory'].replace(session['RootDirectory'], "\\").encode('utf-8')
            else:
                return b'\x03', b''
        else:
            return b'\x02', b''

    # List the contents of the current directory
    def command_LST(self, session):
        try:
            return b'\x01', b','.join(os.listdir(os.fsencode(session['CurrentDirectory'])))
        except:
            return b'\x00', b''

    # Upload file to server
    def command_UPL(self, session, params, payload):
        file_path = os.path.realpath(session['CurrentDirectory'] + params)

        access_violation = False
        try:
            PurePath(file_path).relative_to(os.path.realpath(session['RootDirectory']))
        except ValueError:
            access_violation = True

        if not access_violation:
            params_file = open(file_path, 'ab')
            params_file.write(payload)
            params_file.close()
            return b'\x01', b''
        else:
            return b'\x02', b''

    # Download file from server
    def command_DNL(self, session, params):
        # TODO
        return 1

    # Remove existing file
    def command_RMF(self, session, params):
        if params != "" and params[0] == "\\":
            file_path = PurePath(os.path.realpath(session['RootDirectory'] + params))
        else:
            file_path = PurePath(os.path.realpath(session['CurrentDirectory'] + params))

        access_violation = False
        try:
            file_path.relative_to(os.path.realpath(session['RootDirectory']))
        except ValueError:
            access_violation = True

        if not access_violation:
            if os.path.exists(file_path):
                os.remove(file_path)
                return b'\x01', b''
            else:
                return b'\x03', b''
        else:
            return b'\x02', b''
    # Logout
    def command_LGT(self, msg_src):
        print(f"Logged out from source: {msg_src}")
        self.active_sessions.pop(msg_src, None)
        return b'\x01', b''

    # Unpack methods --------------------------------------------------------------------------------------------------
    def unpack_auth_message(self, msg, session_key):
        # msg NONCE | EKs(SessionID | UNlen | Username | PWlen | Password | Seqclient) | MAC

        nonce = msg[0:16]
        encrypted_payload_with_tag = msg[16:]

        aesgcm = AESGCM(session_key)
        payload = aesgcm.decrypt(nonce, encrypted_payload_with_tag, None)

        close = payload[0]
        session_id = payload[1:9]
        user_name_len = payload[9]
        user_name = payload[10:10 + user_name_len].decode('utf-8')
        password_len = payload[10 + user_name_len]
        password = payload[-(password_len + 16):-16].decode('utf-8')
        sqn_num = payload[-16:]

        return {
            "Nonce": nonce,
            "Close": close,
            "SessionID": session_id,
            "UserName": user_name,
            "Password": password,
            "SequenceNumber": sqn_num
        }

    def unpack_command_message(self, msg, session_key):
        # msg NONCE | EKs (SessionID | Cmd | Plen | Params | Seqserver++) | MAC

        nonce = msg[0:16]
        encrypted_payload_with_tag = msg[16:]

        aesgcm = AESGCM(session_key)
        payload = aesgcm.decrypt(nonce, encrypted_payload_with_tag, None)

        session_id = payload[0:8]
        cmd = Commands(payload[8])

        params_len = int.from_bytes(payload[9:11], 'big')
        params = payload[11:11 + params_len].decode("utf-8")

        cmd_payload = None
        if cmd is Commands.UPL:
            cmd_payload = payload[11 + params_len:-16]
        sqn_num = int.from_bytes(payload[-16:], 'big')

        return {
            "Nonce": nonce,
            "SessionID": session_id,
            "Cmd": cmd,
            "Params": params,
            "Payload": cmd_payload,
            "SequenceNumber": sqn_num
        }


if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], shortopts='hp:a:u:', longopts=['help', 'path=', 'addr=', 'users='])
    except getopt.GetoptError:
        print("Usage: python server.py -p <network path> -a <address>")
        sys.exit(1)

    net_path = "../network/"
    address = "A"
    users_dir = "./users/"

    for opt, arg in opts:
        if opt == '-h' or opt == '--help':
            print("Usage: python server.py -p <network path> -a <address>")
            sys.exit(0)
        elif opt == '-p' or opt == '--path':
            net_path = arg
        elif opt == '-a' or opt == '--addr':
            address = arg
        elif opt == '-u' or opt == '--users':
            users_dir = arg

    server = FTPServer(address, net_path, users_dir)
