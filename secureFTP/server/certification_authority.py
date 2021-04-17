from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from datetime import datetime, timedelta


class CertificationAuthority:
    lt_ca_private_key = None

    def __init__(self):
        # TODO: Attempt to load existing long-term keypair and certificate
        self.lt_ca_private_key = ec.generate_private_key(ec.SECP521R1())

    def request_certificate(self, certificate_info):

        # TODO: Redo with proper certificate signing request instead of dict
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, certificate_info["CommonName"]),
        ]))
        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, u'Example CA Inc.')
        ]))
        builder = builder.not_valid_before(datetime.today() - timedelta(1, 0, 0))
        builder = builder.not_valid_after(datetime.today() + timedelta(365, 0, 0))
        builder = builder.serial_number(x509.random_serial_number())
        builder.public_key(certificate_info["PublicKey"])
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        signed_certificate = builder.sign(
            private_key=self.lt_ca_private_key, algorithm=hashes.SHA512()
        )

        return signed_certificate
