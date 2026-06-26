import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

class TLSManager:
    def __init__(self, cert_dir='certs', cert_file='server.crt', key_file='server.key'):
        self.cert_dir = cert_dir
        self.cert_path = os.path.join(self.cert_dir, cert_file)
        self.key_path = os.path.join(self.cert_dir, key_file)
        
        if not os.path.exists(self.cert_dir):
            os.makedirs(self.cert_dir)

    def generate_self_signed_cert(self, common_name='localhost', days_valid=365):
        """Generates a self-signed certificate and private key."""
        # Generate private key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Generate certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Secure Framework"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days_valid)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]),
            critical=False,
        ).sign(key, hashes.SHA256(), default_backend())

        # Write private key
        with open(self.key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        # Write certificate
        with open(self.cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
            
        return self.cert_path, self.key_path

    def get_cert_status(self):
        """Returns the status and expiry date of the current certificate."""
        if not os.path.exists(self.cert_path):
            return "Missing", None
        
        with open(self.cert_path, "rb") as f:
            cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            
        expiry = cert.not_valid_after_utc
        days_left = (expiry - datetime.datetime.now(datetime.timezone.utc)).days
        
        status = "Valid"
        if days_left < 7:
            status = "Expiring Soon"
        if days_left < 0:
            status = "Expired"
            
        return status, expiry

if __name__ == "__main__":
    manager = TLSManager(cert_dir='../certs')
    cert, key = manager.generate_self_signed_cert()
    print(f"Generated certificate: {cert}")
    print(f"Generated key: {key}")
    status, expiry = manager.get_cert_status()
    print(f"Status: {status}, Expiry: {expiry}")
