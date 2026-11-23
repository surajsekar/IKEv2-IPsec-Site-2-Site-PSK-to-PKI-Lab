#!/usr/bin/env python3
"""
UOWD Root CA - offline certificate authority for the MACS902 GID_09 project.

Built on the Python 'cryptography' library, which uses OpenSSL underneath
for all key generation, hashing and signing.

Usage:
    python3 ikev2_gateway_ca.py init                    create the CA key pair and root certificate
    python3 ikev2_gateway_ca.py sign <router.csr>       check a router's request and issue its certificate
"""

import sys
import datetime
import getpass

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends.openssl import backend
import cryptography

CA_KEY_FILE = "ca_key.pem"     # CA private key, encrypted with a passphrase - never leaves this machine
CA_CERT_FILE = "ca_cert.pem"   # CA root certificate, public - installed on both routers
CA_YEARS = 10                  # root certificate validity
ROUTER_DAYS = 365              # router certificate validity


def banner():
    print(f"cryptography {cryptography.__version__}  |  {backend.openssl_version_text()}")


def now():
    return datetime.datetime.now(datetime.timezone.utc)


# ---------------------------------------------------------------------------
# Step 1 and 2: create the CA key pair and the self-signed root certificate
# ---------------------------------------------------------------------------
def init_ca():
    # Step 1 - CA key pair on the P-384 curve (same curve as DH group 20)
    ca_key = ec.generate_private_key(ec.SECP384R1())

    # Step 2 - root certificate: the CA signs its own public key
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "AE"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UOWD"),
        x509.NameAttribute(NameOID.COMMON_NAME, "UOWD Root CA"),
    ])
    ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)                                   # self-signed: issuer = subject
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now() - datetime.timedelta(minutes=5))
        .not_valid_after(now() + datetime.timedelta(days=365 * CA_YEARS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(ski, critical=False)
        .sign(ca_key, hashes.SHA384())                       # ECDSA with SHA-384
    )

    # Protect the CA private key with a passphrase before writing it to disk
    pw = getpass.getpass("Passphrase to protect the CA private key: ").encode()
    if pw != getpass.getpass("Repeat passphrase: ").encode() or not pw:
        sys.exit("Passphrases empty or do not match - nothing written.")
    with open(CA_KEY_FILE, "wb") as f:
        f.write(ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(pw)))
    with open(CA_CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"CA key pair created (ECDSA P-384)       -> {CA_KEY_FILE} (encrypted)")
    print(f"Root certificate created (ECDSA-SHA384) -> {CA_CERT_FILE}")
    print("SHA-256 fingerprint (check this on each router after 'crypto pki authenticate'):")
    print("  " + cert.fingerprint(hashes.SHA256()).hex(":").upper())


# ---------------------------------------------------------------------------
# Step 4 and 5: check a router's request (CSR) and sign its certificate
# ---------------------------------------------------------------------------
def sign_csr(csr_file):
    with open(CA_CERT_FILE, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    pw = getpass.getpass("CA key passphrase: ").encode()
    try:
        with open(CA_KEY_FILE, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=pw)
    except ValueError:
        sys.exit("Wrong passphrase - CA key not unlocked.")

    # Step 4 - check the request
    try:
        with open(csr_file, "rb") as f:
            csr = x509.load_pem_x509_csr(f.read())
        # 4a. The request must be signed by the router's own private key (proof of possession)
        valid = csr.is_signature_valid
    except Exception:
        sys.exit("REJECTED: request is damaged or unreadable.")
    if not valid:
        sys.exit("REJECTED: request signature is not valid.")
    # 4b. Policy: only ECDSA P-384 keys are accepted
    pub = csr.public_key()
    if not (isinstance(pub, ec.EllipticCurvePublicKey) and isinstance(pub.curve, ec.SECP384R1)):
        sys.exit("REJECTED: only ECDSA P-384 keys are accepted.")
    print(f"Request accepted: {csr.subject.rfc4514_string()}  (ECDSA P-384, signature valid)")

    # Step 5 - sign the router certificate
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)                           # router's identity, as in its request
        .issuer_name(ca_cert.subject)                        # issued by UOWD Root CA
        .public_key(pub)                                     # router's public key; its private key stays on the router
        .serial_number(x509.random_serial_number())          # unique random serial
        .not_valid_before(now() - datetime.timedelta(minutes=5))
        .not_valid_after(now() + datetime.timedelta(days=ROUTER_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
    )
    # Keep the router's alternative names (e.g. its FQDN) if the request carries them
    try:
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        builder = builder.add_extension(san, critical=False)
    except x509.ExtensionNotFound:
        pass

    cert = builder.sign(ca_key, hashes.SHA384())             # ECDSA with SHA-384

    out = csr_file.rsplit(".", 1)[0] + ".crt"
    with open(out, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"Certificate issued -> {out}")
    print(f"  serial  {cert.serial_number:x}")
    print(f"  valid   {cert.not_valid_before_utc:%Y-%m-%d} to {cert.not_valid_after_utc:%Y-%m-%d}")


if __name__ == "__main__":
    banner()
    if len(sys.argv) == 2 and sys.argv[1] == "init":
        init_ca()
    elif len(sys.argv) == 3 and sys.argv[1] == "sign":
        sign_csr(sys.argv[2])
    else:
        print(__doc__)
