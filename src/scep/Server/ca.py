import datetime
import pytz
from typing import Union
from abc import ABCMeta, abstractmethod

from certbuilder import CertificateBuilder
from cryptography import x509

from .._commons import SigningRequest, Certificate, PrivateKey


class CertificateAuthority(object):
    __metaclass__ = ABCMeta

    @property
    @abstractmethod
    def private_key(self) -> Union[None, PrivateKey]:
        """Retrieve the RSA Private key (If available)"""
        pass

    @private_key.setter
    @abstractmethod
    def private_key(self, private_key: PrivateKey):
        pass

    @property
    @abstractmethod
    def ca_certificate(self) -> Union[None, Certificate]:
        """Retrieve the CA Certificate (If available)"""
        pass

    @ca_certificate.setter
    @abstractmethod
    def ca_certificate(self, certificate: Certificate):
        pass

    @property
    @abstractmethod
    def serial(self) -> int:
        """Retrieve the CURRENT serial number (not the next available)."""
        pass

    @serial.setter
    @abstractmethod
    def serial(self, no: int):
        """Set the CURRENT serial number (not the next available)."""
        pass

    @abstractmethod
    def exists(self) -> bool:
        """Does a CA already exist with this storage type?"""
        pass

    @abstractmethod
    def save_issued_certificate(self, certificate: Certificate):
        """Save a certificate that was issued by the CA."""
        pass

    @abstractmethod
    def fetch_issued_certificate(self, serial: int) -> Certificate:
        """Retrieve a certificate that was issued by the CA."""
        pass

    @abstractmethod
    def next_serial_number(self) -> int:
        pass

    def sign(self, csr: SigningRequest) -> Certificate:
        """Sign a certificate signing request.

        Args:
            csr (x509.CertificateSigningRequest): The certificate signing request
        Returns:
            Instance of x509.Certificate
        """
        serial = self.next_serial_number()

        now = datetime.datetime.now(tz=pytz.UTC)

        builder = CertificateBuilder(
            csr.subject,
            csr.public_key.to_asn1_public_key()
        )
        builder.key_usage = csr.key_usage[u'extn_value']
        builder.self_signed = False
        builder.issuer = self.ca_certificate.to_asn1_certificate()
        builder.begin_date = now
        builder.end_date = now + datetime.timedelta(days=365)
        builder.serial_number = serial
        certificate = builder.build(self.private_key.to_asn1_private_key())
        return Certificate(certificate=certificate)

        # builder = builder.subject_name(
        #     x509.Name([
        #         x509.NameAttribute(NameOID.COMMON_NAME, "iOS Client")
        #     ])
        # ).issuer_name(
        #     self.certificate.subject
        # ).not_valid_before(
        #     datetime.datetime.utcnow()
        # ).not_valid_after(
        #     datetime.datetime.utcnow() + datetime.timedelta(days=365)
        # ).serial_number(
        #     serial
        # ).public_key(
        #     csr.public_key()
        # )
        #
        # builder = builder.add_extension(
        #     #  Absolutely critical for SCEP
        #     x509.KeyUsage(
        #         digital_signature=True,
        #         content_commitment=False,
        #         key_encipherment=True,
        #         data_encipherment=False,
        #         key_agreement=False,
        #         key_cert_sign=False,
        #         crl_sign=False,
        #         encipher_only=False,
        #         decipher_only=False
        #     ),
        #     True
        # )
        #
        # # builder = builder.add_extension(
        # #     x509.ExtendedKeyUsage([ObjectIdentifier('1.3.6.1.5.5.8.2.2')]), False
        # # )
        # #
        # # builder = builder.add_extension(
        # #     x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), False
        # # )
        # #
        # # for requested_extension in csr.extensions:
        # #     builder = builder.add_extension(requested_extension.value, critical=requested_extension.critical)
        #
        # cert = builder.sign(self.private_key, hash_functions.get(algorithm, hashes.SHA256)(), default_backend())
        #
        # self._storage.save_issued_certificate(cert)
        # self.serial = serial
        #
        # return cert
