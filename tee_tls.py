import ipaddress
import os
import socket
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from lib.config import config


TLS_DIR = Path(config.base_dir) / "cvm_workflow" / "tls"
CA_CERT_PATH = TLS_DIR / "ca.crt"
CA_KEY_PATH = TLS_DIR / "ca.key"

ROLE_CONFIG = {
    "buffer-server": {
        "common_name": "buffer-tee.local",
        "filename_prefix": "buffer-server",
        "eku": [ExtendedKeyUsageOID.SERVER_AUTH],
    },
    "processing-server": {
        "common_name": "processing-tee.local",
        "filename_prefix": "processing-server",
        "eku": [ExtendedKeyUsageOID.SERVER_AUTH],
    },
    "buffer-client": {
        "common_name": "buffer-client.local",
        "filename_prefix": "buffer-client",
        "eku": [ExtendedKeyUsageOID.CLIENT_AUTH],
    },
    "processing-client": {
        "common_name": "processing-client.local",
        "filename_prefix": "processing-client",
        "eku": [ExtendedKeyUsageOID.CLIENT_AUTH],
    },
}


def tls_debug(message):
    print(f"[TLS setup] {message}", flush=True)


def _dns_names():
    names = {
        "localhost",
        socket.gethostname(),
        socket.getfqdn(),
        os.getenv("COMPUTERNAME", ""),
        os.getenv("HOSTNAME", ""),
    }
    return sorted(name for name in names if name)


def _ip_addresses():
    ips = {"127.0.0.1", "::1"}
    hostname = socket.gethostname()
    for candidate in (hostname, socket.getfqdn(), None):
        try:
            infos = socket.getaddrinfo(candidate, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            continue
        for info in infos:
            address = info[4][0]
            try:
                ipaddress.ip_address(address)
            except ValueError:
                continue
            ips.add(address)
    return sorted(ips)


def _subject(common_name):
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "P3DX Placeholder TLS"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _load_private_key(path):
    with open(path, "rb") as handle:
        return serialization.load_pem_private_key(handle.read(), password=None)


def _write_private_key(path, private_key):
    with open(path, "wb") as handle:
        handle.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )


def _write_certificate(path, certificate):
    with open(path, "wb") as handle:
        handle.write(certificate.public_bytes(serialization.Encoding.PEM))


def _role_paths(role):
    role_config = ROLE_CONFIG[role]
    prefix = role_config["filename_prefix"]
    return {
        "cert": TLS_DIR / f"{prefix}.crt",
        "key": TLS_DIR / f"{prefix}.key",
    }


def _create_ca():
    tls_debug(f"Generating placeholder local CA in {TLS_DIR}")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(_subject("p3dx-local-ca"))
        .issuer_name(_subject("p3dx-local-ca"))
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)
        .sign(private_key, hashes.SHA256())
    )
    _write_private_key(CA_KEY_PATH, private_key)
    _write_certificate(CA_CERT_PATH, certificate)


def _create_role_certificate(role):
    role_config = ROLE_CONFIG[role]
    paths = _role_paths(role)
    tls_debug(f"Generating TLS certificate for role '{role}'")
    ca_private_key = _load_private_key(CA_KEY_PATH)
    with open(CA_CERT_PATH, "rb") as handle:
        ca_certificate = x509.load_pem_x509_certificate(handle.read())

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    san_entries = [x509.DNSName(name) for name in _dns_names()]
    san_entries.extend(x509.IPAddress(ipaddress.ip_address(ip)) for ip in _ip_addresses())

    certificate = (
        x509.CertificateBuilder()
        .subject_name(_subject(role_config["common_name"]))
        .issuer_name(ca_certificate.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage(role_config["eku"]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_private_key, hashes.SHA256())
    )
    _write_private_key(paths["key"], private_key)
    _write_certificate(paths["cert"], certificate)


def ensure_tls_materials(force=False):
    TLS_DIR.mkdir(parents=True, exist_ok=True)
    if force:
        for path in TLS_DIR.glob("*"):
            if path.is_file():
                path.unlink()

    if not CA_CERT_PATH.exists() or not CA_KEY_PATH.exists():
        _create_ca()

    for role in ROLE_CONFIG:
        paths = _role_paths(role)
        if not paths["cert"].exists() or not paths["key"].exists():
            _create_role_certificate(role)

    return {
        "ca_cert": str(CA_CERT_PATH),
        "ca_key": str(CA_KEY_PATH),
        "roles": {
            role: {key: str(value) for key, value in _role_paths(role).items()}
            for role in ROLE_CONFIG
        },
    }


def tls_enabled():
    return os.getenv("TEE_USE_TLS", "1") != "0"


def requests_kwargs(client_role):
    if not tls_enabled():
        return {}
    ensure_tls_materials()
    paths = _role_paths(client_role)
    return {
        "verify": str(CA_CERT_PATH),
        "cert": (str(paths["cert"]), str(paths["key"])),
    }


def build_server_ssl_context(server_role):
    ensure_tls_materials()
    paths = _role_paths(server_role)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(paths["cert"]), keyfile=str(paths["key"]))
    context.load_verify_locations(cafile=str(CA_CERT_PATH))
    if os.getenv("TEE_TLS_REQUEST_CLIENT_CERT", "1") == "1":
        context.verify_mode = ssl.CERT_OPTIONAL
    else:
        context.verify_mode = ssl.CERT_NONE
    return context
