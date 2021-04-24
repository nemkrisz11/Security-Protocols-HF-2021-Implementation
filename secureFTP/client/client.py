from pathlib import Path
from secureFTP.netsim.communicator import Communicator
from secureFTP.server.certification_authority import CertificationAuthority
from secureFTP.protocol.header import *
from secureFTP.protocol.commands import *
from cryptography import x509
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import secrets
import re
import atexit
import os
import sys
import getopt
import argon2


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

    users_dir = None
    current_user_folder = None
    server_working_dir = None

    slash = None

    PARAMS_FILE_NAME = 'params.bin'

    def __init__(self, address, server_address, net_path, users_dir):
        super().__init__(address, net_path)

        os_name = os.name
        if os_name == "nt":
            self.slash = '\\'
        elif os_name == "posix":
            self.slash = '/'
        else:
            print("OS not supported, exiting...")
            sys.exit(1)

        self.server_address = server_address
        self.users_dir = users_dir
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

            print("Please fill out your login information!")
            user_name = input('Username: ')
            password = input('Password: ')

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
                self.current_user_folder = os.path.realpath(self.users_dir + user_name) + self.slash
                Path(self.current_user_folder).mkdir(parents=True, exist_ok=True)
                self.server_working_dir = self.slash
                print("Waiting for commands (type \"help\" for descriptions):")
                self.command_loop()
            elif auth_success == 0:
                print('Authentication failed')
                retry = input('Retry? (y/n) > ')
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
            user_input = input(self.server_working_dir + "> ")

            if user_input == "help":
                self.write_help()
            else:
                try:
                    cmd, param = self.process_user_input(user_input)
                except Exception as ex:
                    print(f"Failed processing input: {ex}")
                    continue

                self.handle_command(cmd, param)

    def process_user_input(self, input):
        words = input.split(' ')

        if len(words) == 0:
            raise Exception("Invalid input")

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
        print("MKD: Creating a folder on the server")
        print("Params: The new folder's {path\}name")
        print("usage: MKD [path]")
        print("\n")
        print("RMD - Removing a folder from the server")
        print("Params: The removable folder's {path\}name")
        print("usage: RMD [path]")
        print("\n")
        print("GWD - Asking for the name of the current folder (working directory) on the server")
        print("Params: -")
        print("usage: GWD")
        print("\n")
        print("CWD - Changing the current folder on the server")
        print("Params: The folder's {path\}name")
        print("usage: CWD [path] ")
        print("\n")
        print("LST - Listing the content of the current folder on the server")
        print("Params: -")
        print("usage: LST")
        print("\n")
        print("UPL - Uploading a file to the server")
        print("Params: The file's {path\}name on the local file system")
        print("usage: UPL [path]")
        print("\n")
        print("DNL - Downloading a file from the server")
        print("Params: The file's {path\}name on the server")
        print("usage: DNL [path]")
        print("\n")
        print("RMF - Removing a file from a folder on the server")
        print("Params: The file's {path\}name on the server")
        print("usage: RMF [path]")
        print("\n")
        print("LGT - Invalidating the current session and logging out")
        print("Params: -")
        print("usage: LGT")

    # Commands --------------------------------------------------------------------------------------------------------
    def handle_command(self, cmd, param):
        if cmd is Commands.MKD:
            self.command_MKD(param)
        elif cmd is Commands.RMD:
            self.command_RMD(param)
        elif cmd is Commands.GWD:
            self.command_GWD()
        elif cmd is Commands.CWD:
            self.command_CWD(param)
        elif cmd is Commands.LST:
            self.command_LST()
        elif cmd is Commands.UPL:
            self.command_UPL(param)
        elif cmd is Commands.DNL:
            self.command_DNL(param)
        elif cmd is Commands.RMF:
            self.command_RMF(param)
        elif cmd is Commands.LGT:
            self.command_LGT()

    def build_msg(self, command, param=None, msg_payload=None):
        self.increment_nonce()

        self.server_sequence += 1

        param_len = 0
        if param:
            param_len = len(param)

        payload = self.session_id + command.value.to_bytes(1, 'big') + param_len.to_bytes(2, 'big')
        if param:
            payload += param.encode('utf-8')
        if msg_payload:
            payload += msg_payload
        payload += self.server_sequence.to_bytes(16, 'big')

        aesgcm = AESGCM(self.session_key)
        enc_payload_with_tag = aesgcm.encrypt(self.nonce, payload, None)
        return enc_payload_with_tag

    def command_MKD(self, param):
        folders = param.split(self.slash)

        valid_names = True
        for folder in folders:
            if not self.validate_folder_name(folder):
                valid_names = False
                break

        if not valid_names:
            print("Invalid folder name, supported characters: A-Z, a-z, 1-9, -, _")
            return

        command = Commands.MKD

        encrypted_msg = self.build_msg(command, param)

        # Send close msg to server
        self.net_if.send_msg(self.server_address, bytes(self.address, 'utf-8') + self.nonce + encrypted_msg)

        # Wait for server response
        _, msg_server_resp = self.net_if.receive_msg(blocking=True)

        try:
            status, response_payload = self.unpack_command_message(msg_server_resp)
        except Exception as ex:
            print(f'Message error for {command.name} command {ex}')
            return

        if status == 1:
            print("Folder successfully created")
        else:
            self.write_command_error(command, status, response_payload.decode('utf-8'))

    def validate_folder_name(self, str):
        search = re.compile(r'[^A-Za-z0-9_\-]').search
        return not bool(search(str))

    def command_RMD(self, param):
        command = Commands.RMD
        encrypted_msg = self.build_msg(command, param)

        # Send close msg to server
        self.net_if.send_msg(self.server_address, bytes(self.address, 'utf-8') + self.nonce + encrypted_msg)

        # Wait for server response
        _, msg_server_resp = self.net_if.receive_msg(blocking=True)

        try:
            status, response_payload = self.unpack_command_message(msg_server_resp)
        except Exception as ex:
            print(f'Message error for {command.name} command {ex}')
            return

        if status == 1:
            print("Folder successfully removed")
        else:
            self.write_command_error(command, status)

    def command_GWD(self):
        command = Commands.GWD
        encrypted_msg = self.build_msg(command)

        # Send close msg to server
        self.net_if.send_msg(self.server_address, bytes(self.address, 'utf-8') + self.nonce + encrypted_msg)

        # Wait for server response
        _, msg_server_resp = self.net_if.receive_msg(blocking=True)

        try:
            status, response_payload = self.unpack_command_message(msg_server_resp)
        except Exception as ex:
            print(f'Message error for {command.name} command {ex}')
            return

        if status == 1:
            self.server_working_dir = response_payload.decode('utf-8')
            print(self.server_working_dir)
        else:
            self.write_command_error(command, status)

    def command_CWD(self, param):
        command = Commands.CWD
        encrypted_msg = self.build_msg(command, param)

        # Send close msg to server
        self.net_if.send_msg(self.server_address, bytes(self.address, 'utf-8') + self.nonce + encrypted_msg)

        # Wait for server response
        _, msg_server_resp = self.net_if.receive_msg(blocking=True)

        try:
            status, response_payload = self.unpack_command_message(msg_server_resp)
        except Exception as ex:
            print(f'Message error for {command.name} command {ex}')
            return

        if status == 1:
            self.server_working_dir = response_payload.decode('utf-8')
        else:
            self.write_command_error(command, status)

    def command_LST(self):
        command = Commands.LST
        encrypted_msg = self.build_msg(command)

        # Send close msg to server
        self.net_if.send_msg(self.server_address, bytes(self.address, 'utf-8') + self.nonce + encrypted_msg)

        # Wait for server response
        _, msg_server_resp = self.net_if.receive_msg(blocking=True)

        try:
            status, response_payload = self.unpack_command_message(msg_server_resp)
        except Exception as ex:
            print(f'Message error for {command.name} command {ex}')
            return

        if status == 1:
            print(response_payload.decode('utf-8'))
        else:
            self.write_command_error(command, status)

    def command_UPL(self, param):
        file_path = os.path.realpath(param)

        if not os.path.exists(file_path):
            print("File doesn't exist")
            return

        reader = open(file_path, "rb")
        file = reader.read()

        file_name = os.path.basename(reader.name)

        print("Enter secret password for encryption")
        key = input()

        salt = secrets.token_bytes(16)
        iv = secrets.token_bytes(16)

        secret_key = argon2.low_level.hash_secret_raw(key.encode('utf-8'),
                                                      salt,
                                                      time_cost=1,
                                                      memory_cost=8,
                                                      parallelism=1,
                                                      hash_len=32,
                                                      type=argon2.low_level.Type.D)

        padder = padding.ANSIX923(128).padder()
        padded_file_content = padder.update(file) + padder.finalize()

        cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted_file = encryptor.update(padded_file_content) + encryptor.finalize()

        digest = hashes.Hash(hashes.SHA256())
        digest.update(encrypted_file)
        file_hash = digest.finalize()

        command = Commands.UPL
        encrypted_msg = self.build_msg(command, file_name, encrypted_file)

        # Send close msg to server
        self.net_if.send_msg(self.server_address, bytes(self.address, 'utf-8') + self.nonce + encrypted_msg)

        # Wait for server response
        _, msg_server_resp = self.net_if.receive_msg(blocking=True)

        try:
            status, response_payload = self.unpack_command_message(msg_server_resp)
        except Exception as ex:
            print(f'Message error for {command.name} command {ex}')
            return

        if status == 1:
            params_file = open(os.path.realpath(self.current_user_folder + self.PARAMS_FILE_NAME), 'ab')
            params_file.write(file_hash + iv + salt)
            params_file.close()

            print("File uploaded")
        else:
            self.write_command_error(command, status)

    def command_DNL(self, param):
        command = Commands.DNL
        encrypted_msg = self.build_msg(command, param)

        # Send close msg to server
        self.net_if.send_msg(self.server_address, bytes(self.address, 'utf-8') + self.nonce + encrypted_msg)

        # Wait for server response
        _, msg_server_resp = self.net_if.receive_msg(blocking=True)

        try:
            status, response_payload = self.unpack_command_message(msg_server_resp)
        except Exception as ex:
            print(f'Message error for {command.name} command {ex}')
            return

        if status == 1:
            try:
                file_content = self.decrypt_file(response_payload)
            except Exception as ex:
                print(f'File decryption error: {ex}')
                return

            file_name = os.path.basename(param)

            downloaded_file = open(os.path.realpath(self.current_user_folder + file_name), 'wb+')
            downloaded_file.write(file_content)
            downloaded_file.close()

            print(f"{file_name} downloaded")
        else:
            self.write_command_error(command, status)

    def decrypt_file(self, encrypted_file):
        print("Enter secret password for decryption")
        key = input()

        digest = hashes.Hash(hashes.SHA256())
        digest.update(encrypted_file)
        file_hash = digest.finalize()

        if not os.path.exists(os.path.realpath(self.current_user_folder + self.PARAMS_FILE_NAME)):
            raise Exception('No params file for decryption')

        reader = open(os.path.realpath(self.current_user_folder + self.PARAMS_FILE_NAME), 'rb')

        iv = None
        salt = None

        line = reader.read(64)
        while line:
            line_hash = line[0:32]
            if line_hash == file_hash:
                iv = line[32:48]
                salt = line[-16:]
            line = reader.read(64)

        if not iv or not salt:
            raise Exception('No params for decryption')

        secret_key = argon2.low_level.hash_secret_raw(key.encode('utf-8'),
                                                      salt,
                                                      time_cost=1,
                                                      memory_cost=8,
                                                      parallelism=1,
                                                      hash_len=32,
                                                      type=argon2.low_level.Type.D)

        cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        file_padded = decryptor.update(encrypted_file) + decryptor.finalize()

        unpadder = padding.ANSIX923(128).unpadder()
        file_content = unpadder.update(file_padded) + unpadder.finalize()

        return file_content

    def command_RMF(self, param):
        command = Commands.RMF
        encrypted_msg = self.build_msg(command, param)

        # Send close msg to server
        self.net_if.send_msg(self.server_address, bytes(self.address, 'utf-8') + self.nonce + encrypted_msg)

        # Wait for server response
        _, msg_server_resp = self.net_if.receive_msg(blocking=True)

        try:
            status, response_payload = self.unpack_command_message(msg_server_resp)
        except Exception as ex:
            print(f'Message error for {command.name} command {ex}')
            return

        if status == 1:
            print("File deleted")
        else:
            self.write_command_error(command, status)

    def command_LGT(self):
        command = Commands.LGT
        encrypted_msg = self.build_msg(command, None)

        # Send close msg to server
        self.net_if.send_msg(self.server_address, bytes(self.address, 'utf-8') + self.nonce + encrypted_msg)

        # Wait for server response
        _, msg_server_resp = self.net_if.receive_msg(blocking=True)

        try:
            status, response_payload = self.unpack_command_message(msg_server_resp)
        except Exception as ex:
            print(f'Message error for {command.name} command {ex}')
            return

        if status == 1:
            self.session_id = None
            self.session_key = None
            self.active_session = False

            print("Logged out")
        else:
            self.write_command_error(command, status)

    def write_command_error(self, cmd, status, error_reason=None):
        if status == 0:
            error_text = f"{cmd.name} failed "
            if error_reason:
                error_text += error_reason
            print(error_text)
        elif status == 2:
            print(f"{cmd.name} access violation")
        elif status == 3:
            print(f"{cmd.name} path not found")

    def increment_nonce(self):
        # Increment the nonce
        nonce = int.from_bytes(self.nonce, 'big')
        nonce += 1
        if nonce >= 2 ** (16 * 8):
            nonce = 0
        elif nonce == int.from_bytes(self.starting_nonce, 'big') - 1:
            print("Message limit reached, exiting...")
            sys.exit(0)

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

        # Proof
        server_proof = msg[idx:idx + 32]
        idx += 32

        # ServerECDHPublicKey
        ecdh_server_public_key_der = msg[idx:idx + 158]
        self.ecdh_server_public_key = serialization.load_der_public_key(ecdh_server_public_key_der)
        idx += 158

        # Sign(Msg)
        signature = msg[idx:]

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


if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], shortopts='hp:a:s:u:', longopts=['help', 'path=', 'addr=', 'server=', 'users='])
    except getopt.GetoptError:
        print("Usage: python client.py -p <network path>")
        sys.exit(1)

    address = 'B'
    server_address = 'A'
    net_path = "../network/"
    users_dir = "./users/"

    for opt, arg in opts:
        if opt == '-h' or opt == '--help':
            print("Usage: python client.py -p <network path> -a <address>")
            sys.exit(0)
        elif opt == '-p' or opt == '--path':
            net_path = arg
        elif opt == '-a' or opt == '--addr':
            address = arg
        elif opt == '-s' or opt == '--server':
            server_address = arg
        elif opt == '-u' or opt == '--users':
            users_dir = arg

    client = FTPClient(address=address, server_address="A", net_path=net_path, users_dir=users_dir)
    client.init_session()
