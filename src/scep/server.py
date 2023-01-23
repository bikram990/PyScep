import array
import os
import logging
import string
from base64 import b64decode
from datetime import datetime
import random

import six
from certbuilder import CertificateBuilder
from flask import Blueprint, abort, g, current_app, request, Response, url_for, Flask
import plistlib

from . import Certificate, SigningRequest, PrivateKey, PKIStatus, Capabilities
from .Server.localca import LocalCA
from ._commons.builders import PKIMessageBuilder, Signer, create_degenerate_pkcs7
from ._commons.enums import MessageType, FailInfo, CACaps
from ._commons.envelope import PKCSPKIEnvelopeBuilder
from ._commons.message import SCEPMessage


logger = logging.getLogger(__name__)
logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)


class MyServer:
    def __int__(self, path):
        self._capabilities = [CACaps.POSTPKIOperation,
                              CACaps.AES, CACaps.DES3,
                              CACaps.SHA1, CACaps.SHA256, CACaps.SHA512,
                              CACaps.Renewal]
        self.ca = LocalCA(base_path=path, password='pyscep')
        self.ca.ca_certificate, self.ca.private_key = MyServer.generate_self_signed(
            cn=u'PyScep-server',
            key_usage={u'digital_signature', u'key_encipherment'}
        )
        logger.info("CA Certificate: {}".format(self.ca.ca_certificate))
        self.ca.save()
        self.users = {}

    def create_challenge(self, name):
        def random_string_generator(str_size, allowed_chars):
            return ''.join(random.choice(allowed_chars) for _ in range(str_size))
        chars = string.ascii_letters + string.punctuation
        size = 12
        self.users[name] = random_string_generator(str_size=size, allowed_chars=chars)

    def dump_request(self):
        dump_dir = current_app.config.get('SCEPY_DUMP_DIR', None)
        if dump_dir is not None and not os.path.exists(dump_dir):
            current_app.logger.debug("Creating dir for request dumps: %s", dump_dir)
            os.mkdir(dump_dir)

        self.dump_filename_prefix = "request-{}".format(datetime.now().timestamp())

    def res_capabilities(self):
        capabilities = '\n'.join([str(capability.value) for capability in self._capabilities])
        print(capabilities)
        return Response(capabilities, mimetype='text/plain')

    def res_ca_cert(self):
        print(self.ca.ca_certificate)
        certs = [self.ca.ca_certificate]

        if len(certs) == 1:
            return Response(certs[0].to_der(), mimetype='application/x-x509-ca-cert')
        elif len(certs):
            raise ValueError('cryptography cannot produce degenerate pkcs7 certs')
            # p7_degenerate = degenerate_pkcs7_der(certs)
            # return Response(p7_degenerate, mimetype='application/x-x509-ca-ra-cert')

    def res_pki_operation(self, pki_request):
        if pki_request.method == 'GET':
            msg = pki_request.args.get('message')
            # note: OS X improperly encodes the base64 query param by not
            # encoding spaces as %2B and instead leaving them as +'s
            msg = b64decode(msg.replace(' ', '+'))
        elif pki_request.method == 'POST':
            # workaround for Flask/Werkzeug lack of chunked handling
            if 'chunked' in pki_request.headers.get('Transfer-Encoding', ''):
                msg = pki_request.environ['body_copy']
            else:
                msg = pki_request.data
        else:
            abort(400, 'Unsupported request method: ' + pki_request.method)
            return

        # if dump_dir is not None:
        #     filename = "{}.bin".format(dump_filename_prefix)
        #     current_app.logger.debug('Dumping request to {}'.format(os.path.join(dump_dir, filename)))
        #     with open(os.path.join(dump_dir, filename), 'wb') as fd:
        #         fd.write(msg)

        req = SCEPMessage.parse(msg)
        current_app.logger.debug('Message Type: %s', req.message_type)
        req.debug()

        if req.message_type == MessageType.PKCSReq or req.message_type == MessageType.RenewalReq:

            csr_der = req.get_decrypted_envelope_data(
                self.ca.ca_certificate,
                self.ca.private_key,
            )

            # if dump_dir is not None:
            #     filename = os.path.join(dump_dir, '{}.csr'.format(dump_filename_prefix))
            #     current_app.logger.debug('Dumping CertificateSigningRequest to {}'.format(os.path.join(dump_dir, filename)))
            #     with open(filename, 'wb') as fd:
            #         fd.write(der_req)
            ca_caps = Capabilities(self._capabilities)
            csr = SigningRequest.from_der(der_string=csr_der)
            signer = Signer(self.ca.ca_certificate, self.ca.private_key, 'sha512')
            current_app.logger.info('Password: ' + csr.challenge_password)
            csr.subject
            if csr.challenge_password != 'sekret':
                current_app.logger.info('Challenge failed')
                pki_msg = PKIMessageBuilder().message_type(
                    MessageType.CertRep
                ).transaction_id(
                    req.transaction_id
                ).pki_status(
                    PKIStatus.FAILURE, FailInfo.BadRequest
                ).recipient_nonce(
                    req.sender_nonce
                ).add_signer(
                    signer
                ).finalize(digest_algorithm=ca_caps.strongest_message_digest())
            else:
                encryption_algo, padding, encrypted_key = req.encryption_info()
                new_cert = self.ca.sign(csr)
                print(new_cert)

                content = create_degenerate_pkcs7(new_cert, self.ca.ca_certificate)

                envelope = PKCSPKIEnvelopeBuilder().encrypt(
                    content.dump(), ca_caps.strongest_cipher(), encryption_algo
                )

                [envelope.add_recipient(certificate=cert) for cert in req.certificates]

                envelope, key, iv = envelope.finalize()

                pki_msg = PKIMessageBuilder().message_type(
                    MessageType.CertRep
                ).pki_envelope(
                    envelope
                ).transaction_id(
                    req.transaction_id
                ).pki_status(
                    PKIStatus.SUCCESS
                ).recipient_nonce(
                    req.sender_nonce
                ).add_signer(
                    signer
                ).finalize(digest_algorithm=ca_caps.strongest_message_digest())

            return Response(pki_msg.dump(), mimetype='application/x-pki-message')

    @classmethod
    def generate_self_signed(cls, cn, key_usage, private_key=None):
        if private_key is None:
            private_key = PrivateKey.generate_pair()

        builder = CertificateBuilder(
            {
                u'common_name': six.text_type(cn),
            },
            private_key.public_key.to_asn1_public_key()
        )
        builder.key_usage = key_usage #[u'digital_signature', u'key_encipherment']
        builder.self_signed = True
        builder.ca = True
        certificate = builder.build(private_key.to_asn1_private_key())
        return Certificate(certificate=certificate), private_key


scep_server = Blueprint('scep_', __name__)


@scep_server.route('/', methods=['GET', 'POST'])
@scep_server.route('/cgi-bin/pkiclient.exe', methods=['GET', 'POST'])
@scep_server.route('/scep', methods=['GET', 'POST'])
def scep():
    op = request.args.get('operation')
    current_app.logger.info("Operation: %s, From: %s, User-Agent: %s", op, request.remote_addr, request.user_agent)

    if op == 'GetCACert':
        return scep_server_obj.res_ca_cert()
    elif op == 'GetCACaps':
        return scep_server_obj.res_capabilities()
    elif op == 'PKIOperation':
        return scep_server_obj.res_pki_operation(request)
    else:
        abort(400, 'Unsupported SCEP operation ' + op)


@scep_server.route('/challenge', methods=['POST'])
def challenge():
    common_name = request.args.get('common_name')
    current_app.logger.info("Creating challenge for %s", common_name)

    if request.method != 'POST':
        abort(400, 'Unsupported method: ' + request.method)

    return scep_server_obj.create_challenge(name=common_name)


@scep_server.route('/mobileconfig')
def mobileconfig():
    """Quick and dirty SCEP enrollment mobileconfiguration profile."""
    my_url = url_for('scep_server.scep', _external=True)

    profile = {
        'PayloadType': 'Configuration',
        'PayloadDisplayName': 'SCEPy Enrolment Test Profile',
        'PayloadDescription': 'This profile will enroll your device with the SCEP server',
        'PayloadVersion': 1,
        'PayloadIdentifier': 'com.github.bikram990.pyscep',
        'PayloadUUID': '7F165A7B-FACE-4A6E-8B56-CA3CC2E9D0BF',
        'PayloadContent': [
            {
                'PayloadType': 'com.apple.security.scep',
                'PayloadVersion': 1,
                'PayloadIdentifier': 'com.github.bikram990.pyscep',
                'PayloadUUID': '16D129CA-DA22-4749-82D5-A28201622555',
                'PayloadDisplayName': 'SCEPy Test Enrolment Payload',
                'PayloadDescription': 'SCEPy Test Enrolment Payload',
                'PayloadContent': {
                    'URL': my_url,
                    'Name': 'SCEPY',
                    'Keysize': 2048,
                    'Key Usage': 5
                }
            }
        ]
    }

    if 'SCEPY_CHALLENGE' in current_app.config:
        profile['PayloadContent'][0]['PayloadContent']['Challenge'] = current_app.config['SCEPY_CHALLENGE']

    return plistlib.dumps(profile), {'Content-Type': 'application/x-apple-aspen-config'}


class WSGIChunkedBodyCopy(object):
    """WSGI wrapper that handles chunked encoding of the request body. Copies
    de-chunked body to a WSGI environment variable called `body_copy` (so best
    not to use with large requests lest memory issues crop up."""
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        wsgi_input = environ.get('wsgi.input')
        if 'chunked' in environ.get('HTTP_TRANSFER_ENCODING', '') and \
                environ.get('CONTENT_LENGTH', '') == '' and \
                wsgi_input:

            body = b''
            sz = int(wsgi_input.readline(), 16)
            while sz > 0:
                body += wsgi_input.read(sz + 2)[:-2]
                sz = int(wsgi_input.readline(), 16)

            environ['body_copy'] = body
            environ['wsgi.input'] = body

        return self.app(environ, start_response)


scep_server_obj = MyServer()
scep_server_obj.__int__(os.getcwd())
scep_server_app = Flask(__name__)
# scep_server.config.from_object('scepy.default_settings')
scep_server_app.config.from_envvar('SCEPY_SETTINGS', True)
scep_server_app.wsgi_app = WSGIChunkedBodyCopy(scep_server_app.wsgi_app)
# app.register_blueprint(admin_app)
scep_server_app.register_blueprint(scep_server)
