from secureFTP.netsim.communicator import Communicator
from secureFTP.protocol.header import *
from cryptography.hazmat.primitives import ciphers, hashes, padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import secrets


class FTPClient(Communicator):
    server_address = None
    ecdh_client_private_key = None
    ecdh_client_public_key = None
    session_id = None
    session_key = None

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
        # Msg = Address | Header | Padded SessionID | CertLen | Cert | Proof | ServerPublicKey | Sign(Msg)
        status, msg_server_init = self.net_if.receive_msg(blocking=True)

        msg_src = msg_server_init[0]
        msg = msg_server_init[1:]

        # Split message
        idx = 0

        header = msg[idx:idx + 16]  # 16 bytes of header
        idx += 16
        if header != init_header:
            print("Header mismatch detected!")
            # TODO : error handling

        padded_session_id = msg[idx:idx + 16]
        unpadder = padding.ANSIX923(256).unpadder()
        self.session_id = unpadder.update(padded_session_id) + unpadder.finalize()
        idx += 16

        server_certificate_length = int.from_bytes(msg[idx:idx + 2], "big")
        idx += 2
        server_certificate = msg[idx:idx + server_certificate_length]
        idx += server_certificate_length

        server_proof = msg[idx:idx + 32]
        idx += 32

        # ...


        # TODO : parse message, validate signature, etc.

        # Construct session key
        """
        shared_secret = ecdh_client_private_key.exchange(
            ec.ECDH(),
            ecdh_server_public_key
        )

        self.session_key = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=None,
            info=b"session_key"
        ).derive(shared_secret)
        """

        # Generate nonce

        # Generate client sequence number

        # Get Username and Password from user

        # Send client authentication message

        # Wait for server response

    def close_session(self):
        pass