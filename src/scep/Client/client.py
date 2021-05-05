import requests
import base64

from asn1crypto.cms import ContentInfo, IssuerAndSerialNumber

from .builders import PKIMessageBuilder, Signer
from .certificate import Certificate
from .crl import RevocationList
from .cryptoutils import digest_for_data
from .envelope import PKCSPKIEnvelopeBuilder
from .responses import EnrollmentStatus, Capabilities, CACertificates
from .message import SCEPMessage
from .enums import CACaps, MessageType, PKIStatus
from .asn1 import IssuerAndSubject


class Client:
    def __init__(self, url):
        self.url = url

    def get_ca_capabilities(self, identifier=None):
        """Query the SCEP Service for its capabilities."""
        message = ''
        if identifier is not None:
            message = identifier

        res = requests.get(self.url, params={'operation': 'GetCACaps', 'message': message})
        if res.status_code != 200:
            raise ValueError('Got invalid status code for GetCACaps: {}'.format(res.status_code))
        caps = res.text.split("\n")
        cacaps = {CACaps(cap.strip()) for cap in caps if cap.strip() != ''}
        return Capabilities(cacaps)

    def get_ca_certs(self, identifier=None):
        """Query the SCEP Service for the CA Certificate."""
        message = ''
        if identifier is not None:
            message = identifier

        res = requests.get(self.url, params={'operation': 'GetCACert', 'message': message})
        if res.status_code != 200:
            raise ValueError('Got invalid status code for GetCACert: {}'.format(res.status_code))
        if res.headers['content-type'] == 'application/x-x509-ca-cert':  # we dont support RA cert yet
            return CACertificates(certificates=[Certificate.from_der(res.content)])
        elif res.headers['content-type'] == 'application/x-x509-ca-ra-cert':  # intermediate via chain
            msg = SCEPMessage.parse(res.content)
            assert len(msg.certificates) > 0
            return CACertificates(certificates=msg.certificates)
        raise ValueError('unknown content-type ' + res.headers['content-type'])

    def rollover_certificate(self, identifier=None):
        """Query the SCEP Service for rollover certificate"""
        message = ''
        if identifier is not None:
            message = identifier

        #FIXME: ensure that the response is signed by the ca cert received in the get_ca_certs
        ca_certs = self.get_ca_certs(identifier=message)

        res = requests.get(self.url, params={'operation': 'GetNextCACert', 'message': message})
        if res.status_code != 200:
            raise ValueError('Got invalid status code for GetCACert: {}'.format(res.status_code))
        assert res.headers['content-type'] == 'application/x-x509-next-ca-cert'
        msg = SCEPMessage.parse(raw=res.content, signer_cert=ca_certs.signer)
        assert len(msg.certificates) > 0
        return [Certificate.from_der(cert) for cert in msg.certificates]

    def get_cert(self, identity, identity_private_key, serial_number, identifier=None):
        """Perform a GetCert operation by submitting certificate serial number to the SCEP service."""
        cacaps = self.get_ca_capabilities(identifier=identifier)
        ca_certs = self.get_ca_certs(identifier=identifier)

        issuer = ca_certs.issuer.subject
        ias = IssuerAndSerialNumber({'issuer': issuer, 'serial_number': serial_number})
        envelope = PKCSPKIEnvelopeBuilder().encrypt(ias.dump(), cacaps.strongest_cipher())

        return self._pki_operation(identity=identity, identity_private_key=identity_private_key, envelope=envelope, message_type=MessageType.GetCert, cacaps=cacaps, ca_certs=ca_certs)

    def poll(self, identity, identity_private_key, subject, transaction_id, identifier=None):
        """Perform a CertPoll operation by submitting subject and transaction id to the SCEP service."""
        cacaps = self.get_ca_capabilities(identifier=identifier)
        ca_certs = self.get_ca_certs(identifier=identifier)

        issuer = ca_certs.issuer.subject
        ias = IssuerAndSubject({'issuer': issuer, 'subject': subject})
        envelope = PKCSPKIEnvelopeBuilder().encrypt(ias.dump(), cacaps.strongest_cipher())

        return self._pki_operation(identity=identity, identity_private_key=identity_private_key, envelope=envelope, message_type=MessageType.CertPoll, cacaps=cacaps, ca_certs=ca_certs, transaction_id=transaction_id)

    def get_crl(self, identity, identity_private_key, serial_number, identifier=None):
        """Perform a GetCRL operation for given serial number from the SCEP service."""
        cacaps = self.get_ca_capabilities(identifier=identifier)
        ca_certs = self.get_ca_certs(identifier=identifier)

        issuer = ca_certs.issuer.subject
        ias = IssuerAndSerialNumber({'issuer': issuer, 'serial_number': serial_number})
        envelope = PKCSPKIEnvelopeBuilder().encrypt(ias.dump(), cacaps.strongest_cipher())

        return self._pki_operation(identity=identity, identity_private_key=identity_private_key, envelope=envelope, message_type=MessageType.GetCRL, cacaps=cacaps, ca_certs=ca_certs)

    def enrol(self, csr, identity, identity_private_key, identifier=None):
        """Perform a PKCSReq operation by submitting a CSR to the SCEP service."""
        cacaps = self.get_ca_capabilities(identifier=identifier)
        ca_certs = self.get_ca_certs(identifier=identifier)
        envelope = PKCSPKIEnvelopeBuilder().encrypt(csr.to_der(), cacaps.strongest_cipher())
        digest = digest_for_data(data=csr.public_key.to_der(), algorithm='sha1')
        transaction_id = digest.encode(encoding='utf-8').hex()
        return self._pki_operation(identity=identity, identity_private_key=identity_private_key, envelope=envelope, message_type=MessageType.PKCSReq, cacaps=cacaps, ca_certs=ca_certs, transaction_id=transaction_id)

    def _pki_operation(self, identity, identity_private_key, envelope, message_type, cacaps, ca_certs, transaction_id=None):
        """Perform a PKIOperation using the PKI Envelope given."""
        envelope = envelope.add_recipient(ca_certs.recipient)

        envelope, key, iv = envelope.finalize()

        signer = Signer(identity, identity_private_key, cacaps.strongest_signature_algorithm())

        pki_msg_builder = PKIMessageBuilder().message_type(
            message_type
        ).pki_envelope(
            envelope
        ).add_signer(
            signer
        ).transaction_id(
            transaction_id
        ).sender_nonce()

        pki_msg = pki_msg_builder.finalize(digest_algorithm=cacaps.strongest_message_digest())

        res = self.__pki_operation(data=pki_msg.dump(), cacaps=cacaps)

        cert_rep = SCEPMessage.parse(raw=res.content, signer_cert=ca_certs.signer)
        # with open('/Volumes/DataDisk/CorporateSources/portal/response', 'rb') as file_handle:
        #     content = file_handle.read()
        # signing_cert = Certificate.from_pem_file('/Volumes/DataDisk/Downloads/embedra_sgn.pem')
        # enc_cert = Certificate.from_pem_file('/Volumes/DataDisk/Downloads/embedra_enc.pem')
        # cert_rep = SCEPMessage.parse(content)
        if cert_rep.pki_status == PKIStatus.FAILURE:
            return EnrollmentStatus(fail_info=cert_rep.fail_info)
        elif cert_rep.pki_status == PKIStatus.PENDING:
            return EnrollmentStatus(transaction_id=cert_rep.transaction_id)
        else:
            decrypted_bytes = cert_rep.get_decrypted_envelope_data(identity, identity_private_key)
            degenerate_info = ContentInfo.load(decrypted_bytes)
            assert degenerate_info['content_type'].native == 'signed_data'
            signed_response = degenerate_info['content']

            certificate = None
            revocation_list = None

            if (message_type is MessageType.PKCSReq) or (message_type is MessageType.GetCert) or (message_type is MessageType.CertPoll):
                certs = signed_response['certificates']
                enrolled_cert = certs[0].chosen
                certificate = Certificate(der_string=enrolled_cert.dump())
            elif message_type is MessageType.GetCRL:
                crls = signed_response['crls']
                received_crl = crls[0].chosen
                revocation_list = RevocationList(revocation_list=received_crl)

            return EnrollmentStatus(certificate=certificate, crl=revocation_list)

    def __pki_operation(self, data, cacaps):
        """Perform a PKIOperation using the CMS data given."""
        headers = {'content-type': 'application/x-pki-message'}
        if cacaps.contains(CACaps.POSTPKIOperation):
            res = requests.post(self.url, params={'operation': 'PKIOperation', 'message': ''}, data=data, headers=headers)
        else:
            b64_bytes = base64.b64encode(data)
            b64_string = b64_bytes.encode('ascii')
            res = requests.get(self.url, params={'operation': 'PKIOperation', 'message': b64_string}, data=data, headers=headers)

        if res.status_code != 200:
            raise ValueError('Got invalid status code for PKIOperation: {}'.format(res.status_code))

        return res