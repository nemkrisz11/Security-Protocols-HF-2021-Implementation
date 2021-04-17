from secureFTP.netsim.communicator import Communicator
from secureFTP.server.certification_authority import CertificationAuthority
from secureFTP.protocol.header import *
from cryptography import x509
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import secrets


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

    def __init__(self, address, server_address, net_path):
        super().__init__(address, net_path)
        self.server_address = server_address
        self.lt_ca_public_key = CertificationAuthority().lt_ca_public_key

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

        msg_server_init_data, signature = self.unpack_init_message(msg_server_init)

        print("Client sig:")
        print(signature)

        # Verify signature, authenticate server
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

        self.login()

    def login(self):

        # Generate nonce
        nonce = secrets.token_bytes(16)

        # Generate client sequence number
        client_sequence_bytes = secrets.token_bytes(8) + bytes(8)

        print('Username:')
        user_name = input()
        print('Password:')
        password = input()

        auth_msg_payload = self.session_id + len(user_name).to_bytes(1, 'big') + user_name.encode('utf-8') \
                           + len(password).to_bytes(1, 'big') + password.encode('utf-8') + client_sequence_bytes

        # creating the cipher
        aesgcm = AESGCM(self.session_key)

        # encrypting payload
        auth_msg_payload_enc_with_tag = aesgcm.encrypt(nonce, auth_msg_payload, None)

        # send auth message to server
        self.net_if.send_msg(self.server_address, bytes(self.address, 'utf-8') + nonce + auth_msg_payload_enc_with_tag)

        # Wait for server response
        status, msg_server_auth_resp = self.net_if.receive_msg(blocking=True)

        # trying to unpack and decipher the received message
        auth_resp = None
        try:
            auth_success, server_sequence = self.unpack_auth_message(msg_server_auth_resp)
        except:
            print(f'Message error for authentication')
            return

        if auth_success == 1:
            print('Authentication successful')
            self.server_sequence = int.from_bytes(server_sequence, 'big')
        elif auth_success == 0:
            print('Authentication failed')
        elif auth_success == 2:
            print('User login locked, try later')

    def unpack_auth_message(self, msg):
        nonce = msg[0:16]
        encrypted_payload_with_tag = msg[16:]

        # creating the cipher
        aesgcm = AESGCM(self.session_key)
        payload = aesgcm.decrypt(nonce, encrypted_payload_with_tag, None)

        auth_success = payload[8]
        server_sequence = None
        if auth_success != 0 or auth_success != 2:
            server_sequence = payload[9:]

        return auth_success, server_sequence

    def unpack_init_message(self, msg_server_init):
        # Msg = Address | Header | Padded SessionID | CertLen | Cert | Proof | ServerECDHPublicKey | Sign(Msg)
        # Address
        msg_src = chr(msg_server_init[0])
        if msg_src != self.server_address:
            print("Server address mismatch detected!")
            # TODO : error handling

        msg = msg_server_init[1:]
        idx = 0

        # Header
        header = msg[idx:idx + 16]
        idx += 16
        if header != init_header:
            print("Header mismatch detected!")
            # TODO : error handling

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
        # server_proof = msg[idx:idx + 32]
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

        return msg[:-len(signature)], signature

    def close_session(self):
        pass
