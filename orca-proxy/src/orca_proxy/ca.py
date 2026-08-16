import datetime
import sqlite3
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .db import now_iso

CA_SUBJECT_NAME = "Orca Local Interception CA"
CA_VALIDITY_YEARS = 10


def get(conn: sqlite3.Connection) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM interception_ca WHERE id = 1").fetchone()


def _generate() -> tuple[str, str, str, datetime.datetime, datetime.datetime]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CA_SUBJECT_NAME)])
    not_before = datetime.datetime.now(datetime.timezone.utc)
    not_after = not_before + datetime.timedelta(days=365 * CA_VALIDITY_YEARS)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    return cert_pem, key_pem, fingerprint, not_before, not_after


def ensure_generated(conn: sqlite3.Connection) -> sqlite3.Row:
    existing = get(conn)
    if existing is not None:
        return existing

    cert_pem, key_pem, fingerprint, not_before, not_after = _generate()
    conn.execute(
        "INSERT INTO interception_ca "
        "(id, certificate_pem, private_key_pem, fingerprint_sha256, not_before, not_after, created_at) "
        "VALUES (1, ?, ?, ?, ?, ?, ?)",
        (cert_pem, key_pem, fingerprint, not_before.isoformat(), not_after.isoformat(), now_iso()),
    )
    return get(conn)


def materialize(row: sqlite3.Row, path: Path) -> None:
    """Atomically write the combined cert+key PEM to the given path."""
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(row["certificate_pem"] + row["private_key_pem"])
    tmp_path.chmod(0o600)
    tmp_path.replace(path)
