import six
from asn1crypto import pem, csr, keys as asn1_keys
from asn1crypto.core import PrintableString
from oscrypto import asymmetric
from csrbuilder import CSRBuilder, _pretty_message, _type_name, pem_armor_csr
from certbuilder import CertificateBuilder

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.hazmat.primitives import serialization

from .privatekey import PrivateKey
from .publickey import PublicKey
from .certificate import Certificate


class ScepCSRBuilder(CSRBuilder):
    _password = None

    @property
    def password(self):
        """
        A unicode strings representing the authentication password.
        """

        return self._password.native

    @password.setter
    def password(self, value):
        if value == '' or value is None:
            self._password = None
        else:
            self._password = PrintableString(value=value)

    def build(self, signing_private_key):
        """
        Validates the certificate information, constructs an X.509 certificate
        and then signs it

        :param signing_private_key:
            An asn1crypto.keys.PrivateKeyInfo or oscrypto.asymmetric.PrivateKey
            object for the private key to sign the request with. This should be
            the private key that matches the public key.

        :return:
            An asn1crypto.csr.CertificationRequest object of the request
        """

        is_oscrypto = isinstance(signing_private_key, asymmetric.PrivateKey)
        if not isinstance(signing_private_key, asn1_keys.PrivateKeyInfo) and not is_oscrypto:
            raise TypeError(_pretty_message(
                '''
                signing_private_key must be an instance of
                asn1crypto.keys.PrivateKeyInfo or
                oscrypto.asymmetric.PrivateKey, not %s
                ''',
                _type_name(signing_private_key)
            ))

        signature_algo = signing_private_key.algorithm
        if signature_algo == 'ec':
            signature_algo = 'ecdsa'

        signature_algorithm_id = '%s_%s' % (self._hash_algo, signature_algo)

        def _make_extension(name, value):
            return {
                'extn_id': name,
                'critical': self._determine_critical(name),
                'extn_value': value
            }

        extensions = []
        for name in sorted(self._special_extensions):
            value = getattr(self, '_%s' % name)
            if value is not None:
                extensions.append(_make_extension(name, value))

        for name in sorted(self._other_extensions.keys()):
            extensions.append(_make_extension(name, self._other_extensions[name]))

        attributes = []
        if extensions:
            attributes.append({
                'type': u'extension_request',
                'values': [extensions]
            })

        if self._password:
            attributes.append({
                'type': u'challenge_password',
                'values': [self._password]
            })

        certification_request_info = csr.CertificationRequestInfo({
            'version': u'v1',
            'subject': self._subject,
            'subject_pk_info': self._subject_public_key,
            'attributes': attributes
        })

        if signing_private_key.algorithm == 'rsa':
            sign_func = asymmetric.rsa_pkcs1v15_sign
        elif signing_private_key.algorithm == 'dsa':
            sign_func = asymmetric.dsa_sign
        elif signing_private_key.algorithm == 'ec':
            sign_func = asymmetric.ecdsa_sign

        if not is_oscrypto:
            signing_private_key = asymmetric.load_private_key(signing_private_key)
        signature = sign_func(signing_private_key, certification_request_info.dump(), self._hash_algo)

        return csr.CertificationRequest({
            'certification_request_info': certification_request_info,
            'signature_algorithm': {
                'algorithm': signature_algorithm_id,
            },
            'signature': signature
        })

class SigningRequest:
    # @classmethod
    # def generate_pair(cls, key_type='rsa', size=2048):
    #     if key_type == 'rsa':
    #         public_key, private_key = asymmetric.generate_pair('rsa', bit_size=size)
    #     elif key_type == 'dsa':
    #         public_key, private_key = asymmetric.generate_pair('dsa', bit_size=size)
    #     elif key_type == 'ec':
    #         public_key, private_key = asymmetric.generate_pair('ec', bit_size=size, curve=u'secp256r1')
    #     else:
    #         raise ValueError('Unsupported key type ' + key_type)
    #
    #     return PrivateKey(private_key=private_key.asn1)

    @classmethod
    def generate_pair(cls, type='rsa', size=2048):
        if type == 'rsa':
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=size,
                backend=default_backend(),
            )
        elif type == 'dsa':
            private_key = dsa.generate_private_key(
                key_size=size,
                backend=default_backend()
            )
        elif type == 'ec':
            private_key = ec.generate_private_key(curve=ec.SECP256R1)
        else:
            raise ValueError('Unsupported key type ' + type)

        der = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return PrivateKey.from_der(der)

    @classmethod
    def generate_csr(cls, cn, key_usage, password=None, private_key=None):
        if private_key is None:
            private_key = cls.generate_pair()

        builder = ScepCSRBuilder(
            {
                u'common_name': six.text_type(cn),
            },
            private_key.public_key.to_asn1_public_key()
        )
        builder.key_usage = key_usage #[u'digital_signature', u'key_encipherment']
        if password:
            builder.password = six.text_type(password)

        request = builder.build(private_key.to_asn1_private_key())

        return SigningRequest(request=request), private_key

    # @classmethod
    # def generate_csr(cls, cn, key_usage, password=None, private_key=None):
    #     """Generate a Certificate Signing Request using a few defaults.
    #
    #     Args:
    #           private_key (rsa.RSAPrivateKey): Optional. If not supplied a key will be generated
    #
    #     Returns:
    #           Tuple of private_key, x509.CertificateSigningRequest
    #     """
    #     if private_key is None:
    #         private_key = cls.generate_pair()
    #
    #     builder = x509.CertificateSigningRequestBuilder()
    #     builder = builder.subject_name(x509.Name([
    #         x509.NameAttribute(NameOID.COMMON_NAME, cn),
    #     ]))
    #     builder = builder.add_extension(
    #         #  Absolutely critical for SCEP
    #         x509.KeyUsage(
    #             digital_signature=True,
    #             content_commitment=False,
    #             key_encipherment=True,
    #             data_encipherment=False,
    #             key_agreement=False,
    #             key_cert_sign=False,
    #             crl_sign=False,
    #             encipher_only=False,
    #             decipher_only=False
    #         ),
    #         True
    #     )
    #
    #     builder.add_extension(x509.UnrecognizedExtension(ObjectIdentifier(u'1.2.840.113549.1.9.7'), bytes(password)), False)
    #
    #     csr = builder.sign(private_key.to_crypto_private_key(), hashes.SHA512(), default_backend())
    #     der_string = csr.public_bytes(serialization.Encoding.DER)
    #     return SigningRequest(der_string=der_string), private_key

    @classmethod
    def generate_self_signed(cls, cn, key_usage, private_key=None):
        if private_key is None:
            private_key = cls.generate_pair()

        builder = CertificateBuilder(
            {
                u'common_name': six.text_type(cn),
            },
            private_key.public_key.to_asn1_public_key()
        )
        builder.key_usage = key_usage #[u'digital_signature', u'key_encipherment']
        builder.self_signed = True
        certificate = builder.build(private_key.to_asn1_private_key())
        return Certificate(certificate=certificate), private_key

    @classmethod
    def from_pem_file(cls, pem_file):
        with open(pem_file, 'rb') as pem_file_handle:
            return cls.from_pem(pem_file_handle.read())

    @classmethod
    def from_pem(cls, pem_string):
        _, _, der_bytes = pem.unarmor(pem_string)
        return cls.from_der(der_bytes)

    @classmethod
    def from_der_file(cls, der_file):
        with open(der_file, 'rb') as der_file_handle:
            return cls.from_der(der_file_handle.read())

    @classmethod
    def from_der(cls, der_string):
        return cls(der_string=der_string)

    def __init__(self, der_string=None, request=None):
        if request is None:
            self._csr = csr.CertificationRequest.load(der_string)
        else:
            self._csr = request

    @property
    def public_key(self):
        return PublicKey(public_key=self._csr[u'certification_request_info'][u'subject_pk_info'])

    def to_der(self):
        return self._csr.dump()

    def to_pem(self):
        return pem_armor_csr(self._csr)

    def to_crypto_csr(self):
        return self._csr
