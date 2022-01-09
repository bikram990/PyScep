# Submission to PyPi

## Submission

### Tutorials
[Python Documentation](https://packaging.python.org/tutorials/packaging-projects/)

[Real Python](https://realpython.com/pypi-publish-python-package/)

[Medium Article](https://medium.com/@joel.barmettler/how-to-upload-your-python-package-to-pypi-65edc5fe9c56)

### Checklist
- Update Version in setup.cfg
- Update download URL in setup.cfg
- Update Version in src/scep/__init__.py
- Commit and Push to Github 
- Create a release on Github

### Commands
````
# Install build package
python -m pip install --upgrade build --user

# Install twine package
python -m pip install --upgrade twine --user

# Build the code
python -m build --wheel

# Upload to test server
python -m twine upload --repository testpypi dist/PyScep-{version}-py2.py3-none-any.whl

# Install from test server
pip install -i https://test.pypi.org/simple/ PyScep=={version}

# Uninstall the test version
pip uninstall PyScep=={version}

# Upload to production server
python -m twine upload --repository pypi dist/PyScep-{version}-py2-none-any.whl

# Install from production server
python -m pip install --upgrade PyScep --user
````

## Helpful examples:
[PKCS7 Detached](https://github.com/jnewbigin/pkcs7_detached)

[CMS Signed Data](https://www.cryptosys.net/pki/manpki/pki_signeddata.html)

[PKCS1](https://github.com/bdauvergne/python-pkcs1)

[SCEPy](https://github.com/mosen/SCEPy)

[SSCEP](https://github.com/certnanny/sscep)

[EST Client](https://github.com/laurentluce/est-client-python)

[Example Search](https://www.programcreek.com/python/example/102802/cryptography.x509)

[jscep](https://github.com/jscep/jscep)

[certbot](https://github.com/certbot/certbot)
