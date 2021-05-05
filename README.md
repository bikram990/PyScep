# PyScep

A Python SCEP Client library to enrol for certificate from a SCEP CA.

**Note: It is intended to be used for testing the environments**

## Getting Started

### Prerequisite
Either Generate a Self Signed Certificate or use an existing Certificate issued by CA

#### Generate a Self Signed Certificate
````
identity, identity_private_key = Client.SigningRequest.generate_self_signed(
    cn=u'PyScep-test',
    key_usage={u'digital_signature', u'key_encipherment'}
)
````
Note: this will generate a new RSA Key pair automatically, you can optionally supply a `private_key`.

#### Load an Existing Certificate
````
identity, identity_private_key = Client.Certificate.from_p12_file(
    pem_file='/path/to/cert.p12', 
    password='password'
)
````

### Signing Request
````
csr, private_key = Client.SigningRequest.generate_csr(
    cn=u'PyScep-test', 
    key_usage={u'digital_signature', u'key_encipherment'}, 
    password='password' 
)
````
Note: this will generate a new RSA Key pair automatically, you can optionally supply a `private_key`.

### Creating a Client
````
client = Client.Client(
    'http://<hostname>:<port>/ejbca/publicweb/apply/scep/pkiclient.exe'
)
````
Above example creates a sample client for [EJBCA](https://www.ejbca.org/). Please update the path according to the CA server in use.

### Enrollment
````
res = client.enrol(
    csr=csr,
    identity=identity, 
    identity_private_key=identity_private_key, 
    identifier=identifier ## An optional identifier how CA Server identifies the CA
)

if res.status == PKIStatus.FAILURE:
    print res.fail_info
elif res.status == PKIStatus.PENDING:
    print res.transaction_id
else:
    print res.certificate
````

### Poll
````
res = client.poll(
    identity=identity,
    identity_private_key=identity_private_key,
    subject=subject,
    transaction_id=transaction_id 
)
````
Response is same as Enrollment.

### Get Certificate
````
res = client.get_cert(
    identity=identity,
    identity_private_key=identity_private_key,
    serial_number=1234567890
)
````
Response is same as Enrollment.

### CRL
````
res = client.get_crl(
    identity=identity,
    identity_private_key=identity_private_key, 
    serial_number=1234567890
)

if res.status == PKIStatus.FAILURE:
    print res.fail_info
elif res.status == PKIStatus.PENDING:
    print res.transaction_id
else:
    print res.crl
````

### Get Rollover Certificate
````
ca_certificate = client.rollover_certificate()
````

## Credits
[SCEPy](https://github.com/mosen/SCEPy) for providing base implementation for this project

[jscep](https://github.com/jscep/jscep) for interface
