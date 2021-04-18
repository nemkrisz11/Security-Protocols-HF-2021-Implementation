from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat
from cryptography.hazmat.primitives.asymmetric import ec
from datetime import datetime, timedelta


class CertificationAuthority:
    lt_ca_private_key = None
    lt_ca_public_key = None

    def __init__(self):
        try:
            with open("./ca_private_key.pem", "rb") as private_key_file:
                self.lt_ca_private_key = serialization.load_pem_private_key(
                    private_key_file.read(), password=b"Example_CA_password")
            with open("./ca_public_key.pem", "rb") as public_key_file:
                self.lt_ca_public_key = serialization.load_pem_public_key(public_key_file.read())

        except FileNotFoundError:
            self.lt_ca_private_key = ec.generate_private_key(ec.SECP521R1())
            self.lt_ca_public_key = self.lt_ca_private_key.public_key()

            with open("./ca_private_key.pem", "wb") as private_key_file:
                private_key_file.write(self.lt_ca_private_key.private_bytes(
                    Encoding.PEM, PrivateFormat.PKCS8, serialization.BestAvailableEncryption(b"Example_CA_password"))
                )
            with open("./ca_public_key.pem", "wb") as public_key_file:
                public_key_file.write(self.lt_ca_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))

    def request_certificate_signing(self, csr):

        csr = x509.load_pem_x509_csr(csr)

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(csr.subject)
        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, u'Example CA Inc.')
        ]))
        builder = builder.not_valid_before(datetime.today() - timedelta(1, 0, 0))
        builder = builder.not_valid_after(datetime.today() + timedelta(365, 0, 0))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(csr.public_key())
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        signed_certificate = builder.sign(
            private_key=self.lt_ca_private_key, algorithm=hashes.SHA512()
        )

        return signed_certificate.public_bytes(serialization.Encoding.PEM)
