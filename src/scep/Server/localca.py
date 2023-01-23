import os
from typing import Union

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from .ca import CertificateAuthority
from .. import Certificate, PrivateKey


class LocalCA(CertificateAuthority):
    _next_serial_number = 100
    _certificate = None
    _private_key = None

    def __init__(self, base_path: str, password: Union[None, str] = None):
        if not os.path.exists(base_path):
            os.mkdir(base_path)

        self._base_path = base_path

        for p in ['certs']:
            if not os.path.exists(os.path.join(base_path, p)):
                os.mkdir(os.path.join(base_path, p))

        ca_path = base_path + '/ca.p12'
        if os.path.exists(ca_path):
            _certificate, _private_key = Certificate.from_p12_file(
                p12_file=ca_path, password=password
            )

        self._issued_path = os.path.join(base_path, 'certs')
        self._password = password

    def exists(self) -> bool:
        return self._certificate is not None and self._private_key is not None

    @property
    def ca_certificate(self) -> Union[None, Certificate]:
        return self._certificate

    @ca_certificate.setter
    def ca_certificate(self, certificate: Certificate):
        print("Updating")
        self._certificate = certificate

    @property
    def private_key(self) -> Union[None, PrivateKey]:
        return self._private_key

    @private_key.setter
    def private_key(self, private_key: PrivateKey):
        self._private_key = private_key

    @property
    def serial(self) -> int:
        return 1  # TODO: READ

    @serial.setter
    def serial(self, no: int):
        with open(self._serial_path, 'w+') as fd:
            fd.write(str(no))

    def save(self):
        pass
        # if self._password is not None:
        #     enc = serialization.BestAvailableEncryption(self._password)
        # else:
        #     enc = serialization.NoEncryption()
        #
        # key_bytes = private_key.private_bytes(
        #     encoding=serialization.Encoding.PEM,
        #     format=serialization.PrivateFormat.PKCS8,
        #     encryption_algorithm=enc
        # )
        #
        # with open(os.path.join(self._key_path), 'wb') as fd:
        #     fd.write(key_bytes)

    def save_issued_certificate(self, certificate: Certificate):
        cert_path = os.path.join(self._issued_path, '{}.cer'.format(certificate.serial_number))
        with open(cert_path, 'wb') as fd:
            fd.write(certificate.to_pem())

    def fetch_issued_certificate(self, serial: int) -> Union[None, Certificate]:
        cert_path = os.path.join(self._issued_path, '{}.cer'.format(serial))
        return Certificate.from_pem_file(cert_path)

    def next_serial_number(self) -> int:
        self._next_serial_number += 1
        return self._next_serial_number
