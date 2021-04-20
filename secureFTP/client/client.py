from secureFTP.netsim.communicator import Communicator
from secureFTP.server.certification_authority import CertificationAuthority
from secureFTP.protocol.header import *
from secureFTP.protocol.commands import *
from cryptography import x509
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import secrets
import re
import atexit

class FTPClient(Communicator):
    server_address = None

    ecdh_client_private_key = None
    ecdh_client_public_key = None
    ecdh_server_public_key = None

    lt_server_public_key = None
    lt_ca_public_key = None

    session_id = None
    session_key = None
    server_certificate = None
    server_sequence = None

    starting_nonce = None
    nonce = None
    client_sequence = None

    active_session = False
    authenticated = False

    def __init__(self, address, server_address, net_path):
        super().__init__(address, net_path)
        self.server_address = server_address
        self.lt_ca_public_key = CertificationAuthority().lt_ca_public_key
        atexit.register(self.exit_handler)

    def exit_handler(self):
        print("Exiting")
        if self.active_session:
            if self.authenticated:
                self.command_LGT()
            else:
                self.close_session()

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

        try:
            msg_server_init_data, signature, server_proof = self.unpack_init_message(msg_server_init)
        except:
            print(f'Message error for session initiation')
            return

        print("Client sig:")
        print(signature)

        # Verify signature and proof, authenticate server
        if client_random != server_proof:
            print("Invalid proof received, closing connection!")
            return

        self.lt_server_public_key.verify(signature, msg_server_init_data, ec.ECDSA(hashes.SHA512()))

        # Construct session key

        shared_secret = self.ecdh_client_private_key.exchange(
            ec.ECDH(),
            self.ecdh_server_public_key
        )

        self.session_key = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=None,
            info=b"session_key"
        ).derive(shared_secret)

        print("Session key in client:")
        print(self.session_key)

        self.active_session = True

        self.login()

    def login(self):
        close = False
        while not close and not self.authenticated:
            # Generate nonce
            if not self.nonce:
                self.starting_nonce = secrets.token_bytes(16)
                self.nonce = self.starting_nonce

            client_sequence_bytes = secrets.token_bytes(8) + bytes(8)
            self.client_sequence = int.from_bytes(client_sequence_bytes, 'big')

            print('Username:')
            user_name = input()
            print('Password:')
            password = input()

            auth_msg_payload = bytes(1) + self.session_id + \
                               len(user_name).to_bytes(1, 'big') + user_name.encode('utf-8') + \
                               len(password).to_bytes(1, 'big') + password.encode('utf-8') + \
                               client_sequence_bytes

            # Creating the cipher
            aesgcm = AESGCM(self.session_key)

            # Encrypting payload
            auth_msg_payload_enc_with_tag = aesgcm.encrypt(self.nonce, auth_msg_payload, None)

            # Send auth message to server
            self.net_if.send_msg(self.server_address,
                                 bytes(self.address, 'utf-8') + self.nonce + auth_msg_payload_enc_with_tag)

            # Wait for server response
            status, msg_server_auth_resp = self.net_if.receive_msg(blocking=True)

            # Trying to unpack and decipher the received message
            try:
                auth_success, server_sequence = self.unpack_auth_message(msg_server_auth_resp)
            except:
                print(f'Message error for authentication')
                return

            if auth_success == 1:
                print('Authentication successful')
                self.server_sequence = int.from_bytes(server_sequence, 'big')
                self.authenticated = True
                self.command_loop()
            elif auth_success == 0:
                print('Authentication failed')
                print('Retry? (y/n)')
                retry = input()
                if retry != 'y':
                    close = True
                    self.close_session()
            elif auth_success == 2:
                print('User login locked, try later')
                close = True
                self.close_session()

    def close_session(self):
        auth_msg_payload = (1).to_bytes(1, 'big') + self.session_id + bytes(1) + bytes(1) + bytes(8)

        # Creating the cipher
        aesgcm = AESGCM(self.session_key)

        # Encrypting payload
        auth_msg_payload_enc_with_tag = aesgcm.encrypt(self.nonce, auth_msg_payload, None)

        # Send auth message to server
        self.net_if.send_msg(self.server_address,
                             bytes(self.address, 'utf-8') + self.nonce + auth_msg_payload_enc_with_tag)

    def command_loop(self):
        while self.active_session:
            print("Waiting for commands (type \"help\" for descriptions):")
            user_input = input()

            if user_input == "help":
                self.write_help()
            else:
                try:
                    cmd, param = self.process_user_input(user_input)
                except Exception as ex:
                    print(f"Failed processing input: {ex}")
                    return

                self.handle_command(cmd, param)


    def process_user_input(self, input):
        words = input.split(' ')

        if len(words) == 0:
            raise Exception("Invalid imput")

        cmd_text = words[0]
        cmd = None
        try:
            cmd = Commands[cmd_text]
        except:
            raise Exception("Invalid command given")

        param = None
        if cmd in [Commands.MKD, Commands.RMD, Commands.CWD, Commands.UPL, Commands.DNL, Commands.RMF]:
            if len(words) != 2:
                raise Exception("Insufficient number of parameters")

            param = words[1]

        return cmd, param


    def write_help(self):
        print("MKD: Creating a folder on the server in the current folder")
        print("Params: The new folder's {path\}name")
        print("usage: MKD [path]")
        print("RMD - Removing a folder from the server")
        print("Params: The removable folder's {path\}name")
        print("usage: RMD [path]")
        print("GWD - Asking for the name of the current folder (working directory) on the server")
        print("Params: -")
        print("usage: GWD")
        print("CWD - Changing the current folder on the server")
        print("Params: The folder's {path\}name")
        print("usage: CWD [path] ")
        print("LST - Listing the content of the current folder on the server")
        print("Params: -")
        print("usage: LST")
        print("UPL - Uploading a file to the server")
        print("Params: The file's {path\}name on the local file system")
        print("usage: UPL [path]")
        print("DNL - Downloading a file from the server")
        print("Params: The file's {path\}name on the server")
        print("usage: DNL [path]")
        print("RMF - Removing a file from a folder on the server")
        print("Params: The file's {path\}name on the server")
        print("usage: RMF [path]")
        print("LGT - Invalidating the current session and logging out")
        print("Params: -")
        print("usage: LGT")

    # Commands --------------------------------------------------------------------------------------------------------
    def handle_command(self, cmd, param):
        if cmd is Commands.MKD:
            self.command_MKD(param)
        elif cmd is Commands.RMD:
            self.command_RMD()
        elif cmd is Commands.GWD:
            self.command_GWD()
        elif cmd is Commands.CWD:
            self.command_CWD(param)
        elif cmd is Commands.LST:
            self.command_LST()
        elif cmd is Commands.UPL:
            self.command_UPL()
        elif cmd is Commands.DNL:
            self.command_DNL()
        elif cmd is Commands.RMF:
            self.command_RMF()
        elif cmd is Commands.LGT:
            self.command_LGT()


    def build_msg_without_payload(self, command, param):
        self.increment_nonce()

        self.server_sequence += 1

        param_len = 0
        if param:
            param_len = len(param)

        payload = self.session_id + command.value.to_bytes(1, 'big') + param_len.to_bytes(2, 'big')
        if param:
            payload += param.encode('utf-8')
        payload += self.server_sequence.to_bytes(16, 'big')

        aesgcm = AESGCM(self.session_key)
        enc_payload_with_tag = aesgcm.encrypt(self.nonce, payload, None)
        return enc_payload_with_tag

    def command_MKD(self, params):
        folders = params.split('\\')

        valid_names = True
        for folder in folders:
            if not self.validate_folder_name(folder):
                valid_names = False
                break

        if not valid_names:
            print("Invalid folder name, supported characters: A-Z, a-z, 1-9, -, _")
            return

        encrypted_msg = self.build_msg_without_payload(Commands.MKD, params)

        # Send close msg to server
        self.net_if.send_msg(self.server_address, bytes(self.address, 'utf-8') + self.nonce + encrypted_msg)

        # Wait for server response
        _, msg_server_resp = self.net_if.receive_msg(blocking=True)

        try:
            status, response_payload = self.unpack_command_message(msg_server_resp)
        except Exception as ex:
            print(f'Message error for GWD command {ex}')
            return

        if status == 1:
            print("Folder successfully created")
        else:
            self.write_command_error(Commands.MKD, status)

    def validate_folder_name(self, str):
        search = re.compile(r'[^A-Za-z0-9_\-]').search
        return not bool(search(str))

    def command_RMD(self):
        pass

    def command_GWD(self):
        encrypted_msg = self.build_msg_without_payload(Commands.GWD, None)

        # Send close msg to server
        self.net_if.send_msg(self.server_address, bytes(self.address, 'utf-8') + self.nonce + encrypted_msg)

        # Wait for server response
        _, msg_server_resp = self.net_if.receive_msg(blocking=True)

        try:
            status, response_payload = self.unpack_command_message(msg_server_resp)
        except Exception as ex:
            print(f'Message error for GWD command {ex}')
            return

        if status == 1:
            print(response_payload.decode('utf-8'))
        else:
            self.write_command_error(Commands.GWD, status)

    def command_CWD(self, param):
        encrypted_msg = self.build_msg_without_payload(Commands.CWD, param)

        # Send close msg to server
        self.net_if.send_msg(self.server_address, bytes(self.address, 'utf-8') + self.nonce + encrypted_msg)

        # Wait for server response
        _, msg_server_resp = self.net_if.receive_msg(blocking=True)

        try:
            status, response_payload = self.unpack_command_message(msg_server_resp)
        except Exception as ex:
            print(f'Message error for GWD command {ex}')
            return

        if status == 1:
            print(response_payload.decode('utf-8'))
        else:
            self.write_command_error(Commands.CWD, status)

    def command_LST(self):
        encrypted_msg = self.build_msg_without_payload(Commands.LST, None)

        # Send close msg to server
        self.net_if.send_msg(self.server_address, bytes(self.address, 'utf-8') + self.nonce + encrypted_msg)

        # Wait for server response
        _, msg_server_resp = self.net_if.receive_msg(blocking=True)

        try:
            status, response_payload = self.unpack_command_message(msg_server_resp)
        except Exception as ex:
            print(f'Message error for LST command {ex}')
            return

        if status == 1:
            print(response_payload.decode('utf-8'))
        else:
            self.write_command_error(Commands.LST, status)

    def command_UPL(self):
        pass

    def command_DNL(self):
        pass

    def command_RMF(self):
        pass

    def command_LGT(self):
        encrypted_msg = self.build_msg_without_payload(Commands.LGT, None)

        # Send close msg to server
        self.net_if.send_msg(self.server_address, bytes(self.address, 'utf-8') + self.nonce + encrypted_msg)

        # Wait for server response
        _, msg_server_close_resp = self.net_if.receive_msg(blocking=True)

        try:
            status, response_payload = self.unpack_command_message(msg_server_close_resp)
        except Exception as ex:
            print(f'Message error for close session {ex}')
            return

        if status == 1:
            self.session_id = None
            self.session_key = None
            self.active_session = False

            print("Logged out")
        else:
            self.write_command_error(Commands.LGT, status)

    def write_command_error(self, cmd, status):
        if status == 0:
            print(f"{cmd.name} failed for unknown reason")
        elif status == 2:
            print(f"{cmd.name} access violation")
        elif status == 3:
            print(f"{cmd.name} path not found")

    def increment_nonce(self):
        # Increment the nonce
        nonce = int.from_bytes(self.nonce, 'big')
        nonce += 1
        if nonce >= 2**(16*8):
            nonce = 0
        elif nonce == self.starting_nonce:
            # nyeh
            pass

        self.nonce = nonce.to_bytes(16, 'big')

    # Unpack methods --------------------------------------------------------------------------------------------------
    def unpack_auth_message(self, msg):
        nonce = msg[0:16]
        encrypted_payload_with_tag = msg[16:]

        # Creating the cipher
        aesgcm = AESGCM(self.session_key)
        payload = aesgcm.decrypt(nonce, encrypted_payload_with_tag, None)

        # Update the nonce
        self.nonce = nonce

        # Skip sessionID
        auth_success = payload[8]
        server_sequence = None
        if auth_success == 1:
            server_sequence = payload[9:]

        return auth_success, server_sequence

    def unpack_init_message(self, msg_server_init):
        # Msg = Address | Header | Padded SessionID | CertLen | Cert | Proof | ServerECDHPublicKey | Sign(Msg)
        # Address
        msg_src = chr(msg_server_init[0])
        if msg_src != self.server_address:
            raise Exception("Server address mismatch detected!")

        msg = msg_server_init[1:]
        idx = 0

        # Header
        header = msg[idx:idx + 16]
        idx += 16
        if header != init_header:
            raise Exception("Header mismatch detected!")

        # SessionID
        padded_session_id = msg[idx:idx + 16]
        unpadder = padding.ANSIX923(128).unpadder()
        self.session_id = unpadder.update(padded_session_id) + unpadder.finalize()
        idx += 16

        # CertLen | Cert
        server_certificate_length = int.from_bytes(msg[idx:idx + 2], "big")
        idx += 2
        self.server_certificate = x509.load_pem_x509_certificate(msg[idx:idx + server_certificate_length])
        idx += server_certificate_length

        self.lt_server_public_key = self.server_certificate.public_key()
        print("Client got server long term public key:")
        print(self.lt_server_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))

        # Proof
        server_proof = msg[idx:idx + 32]
        idx += 32

        # ServerECDHPublicKey
        ecdh_server_public_key_der = msg[idx:idx + 158]
        self.ecdh_server_public_key = serialization.load_der_public_key(ecdh_server_public_key_der)
        idx += 158

        # Sign(Msg)
        signature = msg[idx:]

        print("Client got:")
        ret = msg[:-len(signature)]
        print(msg[:-len(signature)])  # Debug

        return msg[:-len(signature)], signature, server_proof

    def unpack_command_message(self, msg):
        nonce = msg[0:16]
        encrypted_payload_with_tag = msg[16:]

        # Creating the cipher
        aesgcm = AESGCM(self.session_key)
        payload = aesgcm.decrypt(nonce, encrypted_payload_with_tag, None)

        # Skip sessionID
        status = payload[8]
        client_sequence = int.from_bytes(payload[-16:], 'big')

        if self.client_sequence >= client_sequence:
            raise Exception('Invalid sequence number for received message')

        # Update sequence
        self.client_sequence = client_sequence

        # Update the nonce
        self.nonce = nonce

        response_payload = None
        if status == 1:
            response_payload = payload[9:-16]

        return status, response_payload
