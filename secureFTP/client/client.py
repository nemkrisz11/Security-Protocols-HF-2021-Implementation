from secureFTP.netsim.communicator import Communicator
from secureFTP.protocol.header import *
from cryptography import x509
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import secrets


class FTPClient(Communicator):
    server_address = None

    ecdh_client_private_key = None
    ecdh_client_public_key = None
    ecdh_server_public_key = None

    lt_server_public_key = None

    session_id = None
    session_key = None
    server_certificate = None

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

        msg_server_init_data, signature = self.unpack_init_message(msg_server_init)

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

        self.login()

    def login(self):

        # Generate nonce
        nonce = secrets.token_bytes(16)

        # Generate client sequence number
        client_sequence_bytes = secrets.token_bytes(8) + bytes(8)

        # TODO: Get Username and Password from user

        # TODO: Send client authentication message

        # TODO: Wait for server response

    def unpack_init_message(self, msg_server_init):
        # Msg = Address | Header | Padded SessionID | CertLen | Cert | Proof | ServerPublicKey | Sign(Msg)
        # Address
        msg_src = msg_server_init[0]
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
        unpadder = padding.ANSIX923(256).unpadder()
        self.session_id = unpadder.update(padded_session_id) + unpadder.finalize()
        idx += 16

        # CertLen | Cert
        server_certificate_length = int.from_bytes(msg[idx:idx + 2], "big")
        idx += 2
        self.server_certificate = x509.load_pem_x509_certificate(msg[idx:idx + server_certificate_length])
        idx += server_certificate_length

        self.lt_server_public_key = self.server_certificate.public_key()

        # Proof
        # server_proof = msg[idx:idx + 32]
        idx += 32

        # ServerPublicKey
        self.ecdh_server_public_key = msg[idx:idx + 158]
        idx += 158

        # Sign(Msg)
        signature = msg[idx:]

        return msg[:-len(signature)], signature

    def close_session(self):
        pass
