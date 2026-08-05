#!/usr/bin/env python3
"""
File Upload Server for KPH Dynamic Data

HTTP server that handles file uploads, validates PE files and digital signatures,
and stores files on local disk or Alibaba Cloud OSS.

Upload format:
    application/octet-stream: Raw binary file upload

Optional features:
    - X-File-Compressed: gzip header to indicate gzip-compressed file

Usage:
    uv run python upload_server.py [-symboldir=C:/Symbols] [-port=8000] [-debug]

    Or:
    uv run python upload_server.py [-symboldir C:/Symbols] -port 8000 -debug

    OSS storage:
    set KPHTOOLS_SERVER_STORAGE=oss
    uv run python upload_server.py [-port=8000]

    Environment variables are automatically loaded from the .env file next to this script.

    Upload example:
    curl -X POST -H "Content-Type: application/octet-stream" --data-binary "@ntoskrnl.exe" http://localhost:8000/upload

Requirements:
    Python packages:
        Run `uv sync` in the repository root to install project dependencies.
"""

import argparse
import base64
import binascii
import datetime
import gzip
import hashlib
import http.server
import json
import os
import re
import sys
import unicodedata
import warnings
from collections import defaultdict, deque
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path
from typing import Protocol
from urllib.parse import parse_qs, urlparse

try:
    from dotenv import load_dotenv
    import lief
    import pefile
    from asn1crypto import cms, tsp
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, padding, rsa
    from cryptography.utils import CryptographyDeprecationWarning
    from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID
except ImportError as e:
    error_name = getattr(
        e, "name", str(e).split("'")[1] if "'" in str(e) else "unknown"
    )
    print(f"Error: Missing required dependency: {error_name}")
    print(
        "Please run `uv sync` in the repository root to install project dependencies."
    )
    sys.exit(1)

lief.logging.disable()


MAX_FILE_SIZE = 20 * 1024 * 1024  # 20MB
UPLOAD_DIR = "uploads"
DEFAULT_SYMBOL_DIR = "symbols"
ALLOW_FILENAME = ["ntoskrnl.exe", "ntkrnlmp.exe", "ntkrla57.exe"]
ALLOW_FILEDESC = ["NT Kernel & System"]
ALLOW_ARCH = ["x86", "amd64", "arm64"]
SCRIPT_DIR = Path(__file__).resolve().parent
WINDOWS_CODE_SIGNING_CA_PATH = SCRIPT_DIR / "ca" / "windows_code_signing.pem"
EXPECTED_SIGNER_CN = "Microsoft Windows"
EXPECTED_ISSUER_CN = "Microsoft Windows Production PCA 2011"
MAX_CERTIFICATE_CHAIN_DEPTH = 8
MAX_CERTIFICATE_CHAIN_CANDIDATES = 128
MAX_CERTIFICATE_CHAIN_SEARCH_STATES = 1024
MAX_TOTAL_CERTIFICATE_CHAIN_STATES = 4096
MAX_TOTAL_CERTIFICATE_EDGE_VERIFICATIONS = 4096
MAX_TOTAL_CERTIFICATE_PARSES = 1024
MAX_AUTHENTICODE_SIGNATURES = 16
MAX_NESTED_SIGNATURES = 8
MAX_NESTED_SIGNATURE_DEPTH = 4
MAX_SIGNATURE_DER_SIZE = 4 * 1024 * 1024
MAX_TOTAL_SIGNATURE_DER_SIZE = 8 * 1024 * 1024
MAX_SIGNERS_PER_SIGNATURE = 4
MAX_UNSIGNED_ATTRIBUTES_PER_SIGNER = 64
MAX_EMBEDDED_CERTIFICATES_PER_SIGNATURE = 64
MAX_TIMESTAMP_VALUES_PER_SIGNATURE = 16
MAX_CERTIFICATE_DER_SIZE = 128 * 1024
MAX_PE_CERTIFICATE_TABLE_SIZE = 8 * 1024 * 1024
MICROSOFT_TIMESTAMP_TOKEN_OID = "1.3.6.1.4.1.311.3.3.1"
PKCS9_COUNTERSIGNATURE_OID = "1.2.840.113549.1.9.6"
TST_INFO_OID = "1.2.840.113549.1.9.16.1.4"
SIGNING_CERTIFICATE_OID = "1.2.840.113549.1.9.16.2.12"
SIGNING_CERTIFICATE_V2_OID = "1.2.840.113549.1.9.16.2.47"
SUPPORTED_CRITICAL_CERTIFICATE_EXTENSION_OIDS = frozenset(
    {
        ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
        ExtensionOID.SUBJECT_KEY_IDENTIFIER,
        ExtensionOID.KEY_USAGE,
        ExtensionOID.EXTENDED_KEY_USAGE,
        ExtensionOID.BASIC_CONSTRAINTS,
    }
)

PEM_CERTIFICATE_PATTERN = re.compile(
    rb"-----BEGIN CERTIFICATE-----\s*"
    rb"([A-Za-z0-9+/=\r\n]+?)\s*"
    rb"-----END CERTIFICATE-----"
)
PEM_BEGIN_PATTERN = re.compile(rb"-----BEGIN ([^-\r\n]+)-----")
PEM_END_PATTERN = re.compile(rb"-----END ([^-\r\n]+)-----")


class CertificateBundleError(RuntimeError):
    """Raised when the repository code-signing CA bundle is unusable."""


class SignaturePolicyError(RuntimeError):
    """Raised for a fail-closed Authenticode policy decision."""


@dataclass(frozen=True)
class TrustedCertificateBundle:
    """Immutable, audited CA material loaded during server startup."""

    path: Path
    certificates: tuple[x509.Certificate, ...]
    sha256: str
    block_count: int
    duplicate_count: int


@dataclass
class SignatureVerificationBudget:
    """Per-upload budget and caches shared by all signatures and timestamps."""

    remaining_chain_states: int = MAX_TOTAL_CERTIFICATE_CHAIN_STATES
    remaining_edge_verifications: int = MAX_TOTAL_CERTIFICATE_EDGE_VERIFICATIONS
    remaining_certificate_parses: int = MAX_TOTAL_CERTIFICATE_PARSES
    parsed_certificates: dict[bytes, x509.Certificate] = field(default_factory=dict)
    edge_verification_results: dict[tuple[bytes, bytes], bool] = field(
        default_factory=dict
    )
    chain_results: dict[tuple, tuple[x509.Certificate, ...] | None] = field(
        default_factory=dict
    )

    def consume_chain_state(self):
        self.remaining_chain_states -= 1
        if self.remaining_chain_states < 0:
            raise SignaturePolicyError("certificate_chain_total_budget_exceeded")

    def consume_edge_verification(self):
        self.remaining_edge_verifications -= 1
        if self.remaining_edge_verifications < 0:
            raise SignaturePolicyError("certificate_edge_budget_exceeded")

    def consume_certificate_parse(self):
        self.remaining_certificate_parses -= 1
        if self.remaining_certificate_parses < 0:
            raise SignaturePolicyError("certificate_parse_budget_exceeded")


_WINDOWS_CODE_SIGNING_CA_BUNDLE: TrustedCertificateBundle | None = None


# Threaded HTTP server to allow concurrent requests (e.g., uploads + health checks).
class ThreadedHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# Regex pattern for file version: X.X.X.X where X is a ushort (0-65535)
FILEVERSION_PATTERN = re.compile(
    r"^(?:0|[1-9]\d{0,4}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])\."
    r"(?:0|[1-9]\d{0,4}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])\."
    r"(?:0|[1-9]\d{0,4}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])\."
    r"(?:0|[1-9]\d{0,4}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$"
)


class StorageError(Exception):
    """Raised when the configured storage backend cannot complete an operation."""


class StorageBackend(Protocol):
    def stat_file(self, relative_path: str) -> tuple[bool, int | None]:
        """Return whether a file exists and its size when available."""

    def save_file(
        self,
        relative_path: str,
        file_data: bytes,
        file_hash: str,
    ) -> tuple[bool, str, int]:
        """Store a file and return success, message, and HTTP status code."""


def build_symbol_path(arch, file_name, file_version, file_hash):
    """Build the storage-relative path used by all storage backends."""
    return "/".join(
        (
            arch,
            f"{file_name}.{file_version}",
            file_hash,
            file_name,
        )
    )


class DiskStorage:
    """Store uploaded files in the local symbol directory."""

    def __init__(self, symboldir):
        self.symboldir = symboldir

    def _target_path(self, relative_path):
        return os.path.join(self.symboldir, *relative_path.split("/"))

    def stat_file(self, relative_path):
        target_path = self._target_path(relative_path)
        file_exists = os.path.exists(target_path) and os.path.isfile(target_path)
        if not file_exists:
            return (False, None)

        try:
            return (True, os.path.getsize(target_path))
        except OSError:
            return (True, None)

    def save_file(self, relative_path, file_data, file_hash):
        target_path = self._target_path(relative_path)

        if os.path.exists(target_path):
            with open(target_path, "rb") as existing_file:
                existing_data = existing_file.read()

            existing_hash = hashlib.sha256(existing_data).hexdigest().lower()
            if existing_hash == file_hash:
                return (True, "File already exists and is identical", 200)

            return (False, "File already exists with different content", 409)

        target_dir = os.path.dirname(target_path)
        try:
            os.makedirs(target_dir, exist_ok=True)
        except OSError as error:
            return (False, f"Failed to create directory: {error}", 500)

        try:
            with open(target_path, "wb") as target_file:
                target_file.write(file_data)
            return (True, "File uploaded successfully", 200)
        except OSError as error:
            return (False, f"Failed to save file: {error}", 500)


class OssStorage:
    """Store uploaded files in Alibaba Cloud OSS."""

    def __init__(self, client, oss_module, bucket, prefix=""):
        self.client = client
        self.oss = oss_module
        self.bucket = bucket
        self.prefix = prefix.strip().strip("/")

    def _object_key(self, relative_path):
        if self.prefix:
            return f"{self.prefix}/{relative_path}"
        return relative_path

    @staticmethod
    def _unwrap_error(error):
        """Unwrap SDK operation errors to their underlying service error."""
        while hasattr(error, "unwrap"):
            unwrapped_error = error.unwrap()
            if unwrapped_error is None or unwrapped_error is error:
                break
            error = unwrapped_error
        return error

    def _raise_storage_error(self, operation, error):
        status_code = getattr(error, "status_code", None)
        error_code = getattr(error, "code", type(error).__name__)
        request_id = getattr(error, "request_id", None)
        print(
            f"OSS {operation} failed: status={status_code}, "
            f"code={error_code}, request_id={request_id}",
            file=sys.stderr,
        )
        raise StorageError("OSS storage operation failed") from error

    def stat_file(self, relative_path):
        request = self.oss.HeadObjectRequest(
            bucket=self.bucket,
            key=self._object_key(relative_path),
        )
        try:
            result = self.client.head_object(request)
        except Exception as error:  # noqa: BLE001 - SDK wraps transport errors.
            error = self._unwrap_error(error)
            if getattr(error, "code", None) == "NoSuchKey":
                return (False, None)
            self._raise_storage_error("head_object", error)

        return (True, getattr(result, "content_length", None))

    def save_file(self, relative_path, file_data, file_hash):
        file_exists, _ = self.stat_file(relative_path)
        if file_exists:
            return (True, "File already exists and is identical", 200)

        request = self.oss.PutObjectRequest(
            bucket=self.bucket,
            key=self._object_key(relative_path),
            body=BytesIO(file_data),
            content_type="application/octet-stream",
            forbid_overwrite=True,
        )
        try:
            self.client.put_object(request)
        except Exception as error:  # noqa: BLE001 - SDK wraps transport errors.
            error = self._unwrap_error(error)
            if getattr(error, "status_code", None) == 409:
                return (True, "File already exists and is identical", 200)
            self._raise_storage_error("put_object", error)

        return (True, "File uploaded successfully", 200)


def get_storage_mode(environ=None):
    """Read and validate the configured server storage mode."""
    environ = os.environ if environ is None else environ
    storage_mode = environ.get("KPHTOOLS_SERVER_STORAGE", "disk").strip().lower()
    if storage_mode not in ("disk", "oss"):
        raise ValueError("KPHTOOLS_SERVER_STORAGE must be either 'disk' or 'oss'")
    return storage_mode


def create_storage_backend(
    storage_mode,
    symboldir=None,
    environ=None,
    oss_module=None,
):
    """Create the configured storage backend."""
    environ = os.environ if environ is None else environ

    if storage_mode == "disk":
        if not symboldir:
            raise ValueError("symboldir cannot be empty")
        os.makedirs(symboldir, exist_ok=True)
        return DiskStorage(symboldir)

    if storage_mode != "oss":
        raise ValueError(f"Unsupported storage mode: {storage_mode}")

    required_variables = (
        "KPHTOOLS_SERVER_OSS_REGION",
        "KPHTOOLS_SERVER_OSS_BUCKET",
        "OSS_ACCESS_KEY_ID",
        "OSS_ACCESS_KEY_SECRET",
    )
    missing_variables = [
        name for name in required_variables if not environ.get(name, "").strip()
    ]
    if missing_variables:
        raise ValueError(
            "Missing required OSS environment variables: "
            + ", ".join(missing_variables)
        )

    if oss_module is None:
        try:
            import alibabacloud_oss_v2 as oss_module
        except ImportError as error:
            raise RuntimeError(
                "Missing OSS dependency: run `uv sync` in the repository root"
            ) from error

    credentials_provider = (
        oss_module.credentials.EnvironmentVariableCredentialsProvider()
    )
    config = oss_module.config.load_default()
    config.credentials_provider = credentials_provider
    config.region = environ["KPHTOOLS_SERVER_OSS_REGION"].strip()

    endpoint = environ.get("KPHTOOLS_SERVER_OSS_ENDPOINT", "").strip()
    if endpoint:
        config.endpoint = endpoint

    client = oss_module.Client(config)
    return OssStorage(
        client,
        oss_module,
        environ["KPHTOOLS_SERVER_OSS_BUCKET"].strip(),
        environ.get("KPHTOOLS_SERVER_OSS_PREFIX", ""),
    )


def validate_exists_params(arch, filename, fileversion, sha256):
    """
    Validate parameters for /exists endpoint.

    Args:
        arch: Architecture string
        filename: Filename string
        fileversion: File version string
        sha256: SHA256 hash string (lowercase, 64 hex characters)

    Returns:
        Tuple of (is_valid: bool, error_message: str or None)
    """
    # Validate arch
    if arch not in ALLOW_ARCH:
        return (False, f"Invalid arch: must be one of {ALLOW_ARCH}")

    # Validate filename (case-insensitive)
    if filename.lower() not in [name.lower() for name in ALLOW_FILENAME]:
        return (False, f"Invalid filename: must be one of {ALLOW_FILENAME}")

    # Validate fileversion format: X.X.X.X where X is ushort (0-65535)
    if not FILEVERSION_PATTERN.match(fileversion):
        return (
            False,
            "Invalid fileversion: must be in format X.X.X.X where X is 0-65535",
        )

    # Validate sha256 format: 64 lowercase hex characters
    if len(sha256) != 64 or not all(c in "0123456789abcdef" for c in sha256.lower()):
        return (False, "Invalid sha256: must be 64 lowercase hexadecimal characters")

    return (True, None)


def check_file_exists(storage, arch, filename, fileversion, sha256):
    """
    Check if a file exists in the symbol directory.

    Args:
        storage: Configured storage backend
        arch: Architecture (x86/amd64/arm64)
        filename: Filename to check
        fileversion: File version string
        sha256: SHA256 hash of the file (lowercase)

    Returns:
        Dictionary with file existence information:
        {
            'filename': str,
            'arch': str,
            'fileversion': str,
            'sha256': str,
            'exists': bool,
            'path': str,
            'file_size': int (optional, only if file exists)
        }
    """
    relative_path = build_symbol_path(
        arch,
        filename,
        fileversion,
        sha256,
    )
    file_exists, file_size = storage.stat_file(relative_path)

    # Prepare response data
    result = {
        "filename": filename,
        "arch": arch,
        "fileversion": fileversion,
        "sha256": sha256,
        "exists": file_exists,
        "path": relative_path,
    }

    if file_exists and file_size is not None:
        result["file_size"] = file_size

    return result


def parse_args(argv=None):
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="HTTP server that handles file uploads, validates PE files and digital signatures"
    )
    parser.add_argument(
        "-symboldir",
        default=DEFAULT_SYMBOL_DIR,
        help=(
            f"Directory to store uploaded files in disk mode (default: {DEFAULT_SYMBOL_DIR}; "
            "can be overridden by KPHTOOLS_SYMBOLDIR)"
        ),
    )
    parser.add_argument(
        "-port",
        type=int,
        default=8000,
        help="Port to listen on (default: 8000, can also be set via KPHTOOLS_SERVER_PORT environment variable)",
    )
    parser.add_argument(
        "-debug",
        action="store_true",
        help="Enable debug mode (includes HTTP request logging)",
    )

    args = parser.parse_args(argv)

    env_symboldir = os.environ.get("KPHTOOLS_SYMBOLDIR")
    if env_symboldir is not None:
        args.symboldir = env_symboldir
    if not args.symboldir:
        parser.error("-symboldir cannot be empty")

    return args


def _parse_certificate_bundle(raw_data, source_path):
    """Parse and deduplicate the repository PEM bundle without using system trust."""
    source_path = Path(source_path).resolve()
    if not raw_data or not raw_data.strip():
        raise CertificateBundleError(f"{source_path}: CA bundle is empty")

    begin_labels = PEM_BEGIN_PATTERN.findall(raw_data)
    end_labels = PEM_END_PATTERN.findall(raw_data)
    if any(label != b"CERTIFICATE" for label in begin_labels + end_labels):
        raise CertificateBundleError(
            f"{source_path}: CA bundle contains a non-certificate PEM block"
        )

    matches = list(PEM_CERTIFICATE_PATTERN.finditer(raw_data))
    if len(begin_labels) != len(end_labels) or len(begin_labels) != len(matches):
        raise CertificateBundleError(
            f"{source_path}: CA bundle contains a truncated or malformed PEM block"
        )
    if not matches:
        raise CertificateBundleError(
            f"{source_path}: CA bundle contains no certificate blocks"
        )

    certificates = []
    seen_fingerprints = set()
    duplicate_count = 0
    for block_index, match in enumerate(matches, 1):
        payload = re.sub(rb"\s+", b"", match.group(1))
        try:
            der_data = base64.b64decode(payload, validate=True)
        except (binascii.Error, ValueError) as error:
            raise CertificateBundleError(
                f"{source_path}: certificate block {block_index} has invalid base64"
            ) from error
        if not der_data:
            raise CertificateBundleError(
                f"{source_path}: certificate block {block_index} is empty"
            )

        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", CryptographyDeprecationWarning)
                certificate = x509.load_der_x509_certificate(der_data)
        except (TypeError, ValueError) as error:
            raise CertificateBundleError(
                f"{source_path}: certificate block {block_index} failed X.509 parsing "
                f"({type(error).__name__})"
            ) from error

        fingerprint = certificate.fingerprint(hashes.SHA256())
        if fingerprint in seen_fingerprints:
            duplicate_count += 1
            continue
        seen_fingerprints.add(fingerprint)
        certificates.append(certificate)

    if not certificates:
        raise CertificateBundleError(
            f"{source_path}: CA bundle contains no unique certificates"
        )

    return TrustedCertificateBundle(
        path=source_path,
        certificates=tuple(certificates),
        sha256=hashlib.sha256(raw_data).hexdigest().upper(),
        block_count=len(matches),
        duplicate_count=duplicate_count,
    )


def load_windows_code_signing_ca_bundle():
    """Load the sole production trust source from the repository."""
    ca_path = WINDOWS_CODE_SIGNING_CA_PATH.resolve()
    try:
        raw_data = ca_path.read_bytes()
    except OSError as error:
        raise CertificateBundleError(
            f"{ca_path}: unable to read CA bundle ({type(error).__name__})"
        ) from error
    return _parse_certificate_bundle(raw_data, ca_path)


def preflight_windows_code_signing_ca_bundle():
    """Load and cache trusted CA material before the HTTP server is created."""
    global _WINDOWS_CODE_SIGNING_CA_BUNDLE
    bundle = load_windows_code_signing_ca_bundle()
    _WINDOWS_CODE_SIGNING_CA_BUNDLE = bundle
    print(f"Windows code-signing CA bundle: {bundle.path}")
    print(
        "Windows code-signing CA certificates: "
        f"{len(bundle.certificates)} unique from {bundle.block_count} blocks "
        f"({bundle.duplicate_count} duplicates removed)"
    )
    print(f"Windows code-signing CA SHA-256: {bundle.sha256}")
    return bundle


def _certificate_fingerprint(certificate):
    return certificate.fingerprint(hashes.SHA256())


def _name_lookup_key(name):
    normalized_rdns = []
    for relative_distinguished_name in name.rdns:
        normalized_attributes = []
        for attribute in relative_distinguished_name:
            value = attribute.value
            if isinstance(value, str):
                value = " ".join(
                    unicodedata.normalize("NFKC", value).split()
                ).casefold()
            normalized_attributes.append((attribute.oid.dotted_string, value))
        normalized_rdns.append(tuple(sorted(normalized_attributes)))
    return tuple(normalized_rdns)


def _distinguished_names_match(left, right):
    return _name_lookup_key(left) == _name_lookup_key(right)


def _certificate_critical_extensions_are_supported(certificate):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", CryptographyDeprecationWarning)
        return all(
            not extension.critical
            or extension.oid in SUPPORTED_CRITICAL_CERTIFICATE_EXTENSION_OIDS
            for extension in certificate.extensions
        )


def _certificate_public_key_is_bounded(certificate):
    public_key = certificate.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        return public_key.key_size <= 8192
    if isinstance(public_key, dsa.DSAPublicKey):
        return public_key.key_size <= 3072
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return public_key.key_size <= 521
    return False


def _certificate_valid_at(certificate, validation_time):
    return (
        certificate.not_valid_before_utc
        <= validation_time
        <= certificate.not_valid_after_utc
    )


def _certificate_is_ca(certificate):
    try:
        constraints = certificate.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
    except x509.ExtensionNotFound:
        return False
    return constraints.ca


def _require_code_signing_certificate_profile(certificate):
    try:
        basic_constraints = certificate.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
    except x509.ExtensionNotFound as error:
        raise SignaturePolicyError(
            "signer_certificate_missing_basic_constraints"
        ) from error
    if basic_constraints.ca:
        raise SignaturePolicyError("signer_certificate_is_ca")

    try:
        extended_key_usage = certificate.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE
        ).value
    except x509.ExtensionNotFound as error:
        raise SignaturePolicyError("signer_certificate_missing_eku") from error
    if ExtendedKeyUsageOID.CODE_SIGNING not in extended_key_usage:
        raise SignaturePolicyError("signer_certificate_wrong_eku")

    try:
        key_usage = certificate.extensions.get_extension_for_oid(
            ExtensionOID.KEY_USAGE
        ).value
    except x509.ExtensionNotFound:
        return
    if not (key_usage.digital_signature or key_usage.content_commitment):
        raise SignaturePolicyError("signer_certificate_wrong_key_usage")


def _certificate_can_issue(
    certificate,
    *,
    is_trust_anchor,
    ca_certificates_below,
    required_extended_key_usage,
):
    try:
        constraints = certificate.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
    except x509.ExtensionNotFound:
        if not is_trust_anchor:
            return False
    else:
        if not constraints.ca:
            return False
        if (
            constraints.path_length is not None
            and ca_certificates_below > constraints.path_length
        ):
            return False

    try:
        key_usage = certificate.extensions.get_extension_for_oid(
            ExtensionOID.KEY_USAGE
        ).value
    except x509.ExtensionNotFound:
        pass
    else:
        if not key_usage.key_cert_sign:
            return False

    try:
        extended_key_usage = certificate.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE
        ).value
    except x509.ExtensionNotFound:
        pass
    else:
        if (
            required_extended_key_usage is not None
            and required_extended_key_usage not in extended_key_usage
            and ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE not in extended_key_usage
        ):
            return False
    return _certificate_critical_extensions_are_supported(
        certificate
    ) and _certificate_public_key_is_bounded(certificate)


def _certificate_was_issued_by(certificate, issuer):
    if not _distinguished_names_match(certificate.issuer, issuer.subject):
        return False

    try:
        authority_key_identifier = certificate.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER
        ).value.key_identifier
        subject_key_identifier = issuer.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        ).value.digest
    except x509.ExtensionNotFound:
        pass
    else:
        if (
            authority_key_identifier is not None
            and authority_key_identifier != subject_key_identifier
        ):
            return False

    public_key = issuer.public_key()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            signature_parameters = certificate.signature_algorithm_parameters
            if signature_parameters is None:
                signature_parameters = padding.PKCS1v15()
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                signature_parameters,
                certificate.signature_hash_algorithm,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            signature_parameters = certificate.signature_algorithm_parameters
            if signature_parameters is None:
                signature_parameters = ec.ECDSA(certificate.signature_hash_algorithm)
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                signature_parameters,
            )
        elif isinstance(public_key, dsa.DSAPublicKey):
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                certificate.signature_hash_algorithm,
            )
        else:
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
            )
    except (
        InvalidSignature,
        TypeError,
        UnsupportedAlgorithm,
        ValueError,
        x509.UnsupportedGeneralNameType,
    ):
        return False
    return True


def _build_trusted_certificate_chain(
    leaf_certificate,
    intermediate_certificates,
    trusted_bundle,
    validation_time,
    *,
    required_extended_key_usage=None,
    budget=None,
):
    """Build a chain whose final certificate is from the repository bundle."""
    if budget is None:
        budget = SignatureVerificationBudget()
    if validation_time.tzinfo is None:
        raise SignaturePolicyError("certificate_validation_time_missing_timezone")
    validation_time = validation_time.astimezone(datetime.timezone.utc)

    trust_anchors = {
        _certificate_fingerprint(certificate): certificate
        for certificate in trusted_bundle.certificates
    }
    candidates = {}
    for certificate in (*intermediate_certificates, *trusted_bundle.certificates):
        candidates.setdefault(_certificate_fingerprint(certificate), certificate)

    if len(candidates) > MAX_CERTIFICATE_CHAIN_CANDIDATES:
        raise SignaturePolicyError("certificate_chain_candidate_limit_exceeded")

    candidates_by_subject = defaultdict(list)
    subject_key_identifiers = {}
    for fingerprint, certificate in candidates.items():
        candidates_by_subject[_name_lookup_key(certificate.subject)].append(
            (fingerprint, certificate)
        )
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", CryptographyDeprecationWarning)
            try:
                subject_key_identifiers[fingerprint] = (
                    certificate.extensions.get_extension_for_oid(
                        ExtensionOID.SUBJECT_KEY_IDENTIFIER
                    ).value.digest
                )
            except x509.ExtensionNotFound:
                subject_key_identifiers[fingerprint] = None

    chain_cache_key = (
        _certificate_fingerprint(leaf_certificate),
        tuple(sorted(candidates)),
        trusted_bundle.sha256,
        validation_time,
        required_extended_key_usage,
    )
    if chain_cache_key in budget.chain_results:
        return budget.chain_results[chain_cache_key]

    failed_states = set()
    searched_states = 0

    def walk(current, chain, ca_certificates_below):
        nonlocal searched_states
        current_fingerprint = _certificate_fingerprint(current)
        visited = frozenset(
            _certificate_fingerprint(certificate) for certificate in chain
        )
        state = (current_fingerprint, ca_certificates_below, visited)
        if state in failed_states:
            return None
        searched_states += 1
        budget.consume_chain_state()
        if searched_states > MAX_CERTIFICATE_CHAIN_SEARCH_STATES:
            raise SignaturePolicyError("certificate_chain_search_limit_exceeded")
        if not _certificate_valid_at(current, validation_time):
            failed_states.add(state)
            return None
        if not _certificate_critical_extensions_are_supported(current):
            failed_states.add(state)
            return None
        if not _certificate_public_key_is_bounded(current):
            failed_states.add(state)
            return None
        if current_fingerprint in trust_anchors:
            if len(chain) > 1 or _certificate_is_ca(current):
                return tuple(chain)
            failed_states.add(state)
            return None
        if len(chain) >= MAX_CERTIFICATE_CHAIN_DEPTH:
            failed_states.add(state)
            return None

        current_is_ca = _certificate_is_ca(current)
        current_is_self_issued = _distinguished_names_match(
            current.subject,
            current.issuer,
        )
        parent_ca_certificates_below = ca_certificates_below + (
            1 if current_is_ca and not current_is_self_issued else 0
        )
        try:
            authority_key_identifier = current.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_KEY_IDENTIFIER
            ).value.key_identifier
        except x509.ExtensionNotFound:
            authority_key_identifier = None
        possible_parents = candidates_by_subject.get(
            _name_lookup_key(current.issuer),
            (),
        )
        if authority_key_identifier is not None:
            possible_parents = sorted(
                possible_parents,
                key=lambda pair: (
                    subject_key_identifiers[pair[0]] != authority_key_identifier
                ),
            )
        for parent_fingerprint, parent in possible_parents:
            if parent_fingerprint in visited:
                continue
            is_trust_anchor = parent_fingerprint in trust_anchors
            if not _certificate_can_issue(
                parent,
                is_trust_anchor=is_trust_anchor,
                ca_certificates_below=parent_ca_certificates_below,
                required_extended_key_usage=required_extended_key_usage,
            ):
                continue
            edge_cache_key = (current_fingerprint, parent_fingerprint)
            if edge_cache_key not in budget.edge_verification_results:
                budget.consume_edge_verification()
                budget.edge_verification_results[edge_cache_key] = (
                    _certificate_was_issued_by(current, parent)
                )
            if not budget.edge_verification_results[edge_cache_key]:
                continue
            result = walk(
                parent,
                [*chain, parent],
                parent_ca_certificates_below,
            )
            if result is not None:
                return result
        failed_states.add(state)
        return None

    result = walk(leaf_certificate, [leaf_certificate], 0)
    budget.chain_results[chain_cache_key] = result
    return result


def _load_cryptography_certificate(raw_der, error_code, *, budget=None):
    if len(raw_der) > MAX_CERTIFICATE_DER_SIZE:
        raise SignaturePolicyError("certificate_der_size_limit_exceeded")
    cache_key = hashlib.sha256(raw_der).digest()
    if budget is not None and cache_key in budget.parsed_certificates:
        return budget.parsed_certificates[cache_key]
    if budget is not None:
        budget.consume_certificate_parse()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", CryptographyDeprecationWarning)
            certificate = x509.load_der_x509_certificate(raw_der)
    except (TypeError, ValueError) as error:
        raise SignaturePolicyError(error_code) from error
    if not _certificate_public_key_is_bounded(certificate):
        raise SignaturePolicyError("certificate_public_key_limit_exceeded")
    if budget is not None:
        budget.parsed_certificates[cache_key] = certificate
    return certificate


def _single_common_name(name):
    common_names = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(common_names) != 1:
        return None
    return common_names[0].value


def _hash_algorithm(name):
    algorithms = {
        "sha1": hashes.SHA1,
        "sha224": hashes.SHA224,
        "sha256": hashes.SHA256,
        "sha384": hashes.SHA384,
        "sha512": hashes.SHA512,
    }
    algorithm = algorithms.get(name)
    if algorithm is None:
        raise SignaturePolicyError("unsupported_timestamp_digest_algorithm")
    return algorithm()


def _digest_bytes(data, algorithm_name):
    digest = hashes.Hash(_hash_algorithm(algorithm_name))
    digest.update(data)
    return digest.finalize()


def _cms_certificate_pairs(certificate_set, *, budget=None):
    pairs = []
    if certificate_set is None or len(certificate_set) == 0:
        return pairs
    if len(certificate_set) > MAX_EMBEDDED_CERTIFICATES_PER_SIGNATURE:
        raise SignaturePolicyError("cms_certificate_limit_exceeded")
    for certificate_choice in certificate_set:
        if certificate_choice.name == "v2_attr_cert":
            continue
        if certificate_choice.name != "certificate":
            raise SignaturePolicyError("unsupported_cms_certificate_choice")
        asn1_certificate = certificate_choice.chosen
        crypto_certificate = _load_cryptography_certificate(
            asn1_certificate.dump(),
            "timestamp_certificate_parse_failed",
            budget=budget,
        )
        pairs.append((asn1_certificate, crypto_certificate))
    return pairs


def _find_cms_signer_certificate(signer_info, certificate_pairs):
    signer_identifier = signer_info["sid"]
    if signer_identifier.name != "issuer_and_serial_number":
        raise SignaturePolicyError("unsupported_cms_signer_identifier")
    issuer_and_serial = signer_identifier.chosen
    matches = [
        crypto_certificate
        for asn1_certificate, crypto_certificate in certificate_pairs
        if (
            asn1_certificate.serial_number == issuer_and_serial["serial_number"].native
            and asn1_certificate.issuer.dump() == issuer_and_serial["issuer"].dump()
        )
    ]
    if len(matches) != 1:
        raise SignaturePolicyError("cms_signer_certificate_not_unique")
    return matches[0]


def _cms_attribute_values(attributes, attribute_oid):
    if attributes is None or len(attributes) == 0:
        return []
    values = []
    for attribute in attributes:
        if attribute["type"].dotted == attribute_oid:
            values.extend(attribute["values"])
    return values


def _single_cms_attribute_value(attributes, attribute_oid, error_code):
    values = _cms_attribute_values(attributes, attribute_oid)
    if len(values) != 1:
        raise SignaturePolicyError(error_code)
    return values[0]


def _verify_cms_signer_signature(signer_info, signer_certificate, signed_content):
    digest_algorithm_name = signer_info["digest_algorithm"]["algorithm"].native
    digest_algorithm = _hash_algorithm(digest_algorithm_name)
    signed_attributes = signer_info["signed_attrs"]
    if len(signed_attributes) == 0:
        signed_data = signed_content
    else:
        encoded_attributes = bytearray(signed_attributes.dump())
        if not encoded_attributes or encoded_attributes[0] != 0xA0:
            raise SignaturePolicyError("malformed_cms_signed_attributes")
        encoded_attributes[0] = 0x31
        signed_data = bytes(encoded_attributes)

    signature_algorithm = signer_info["signature_algorithm"]["algorithm"].native
    signature = signer_info["signature"].native
    public_key = signer_certificate.public_key()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            if signature_algorithm not in {
                "rsassa_pkcs1v15",
                "sha1_rsa",
                "sha224_rsa",
                "sha256_rsa",
                "sha384_rsa",
                "sha512_rsa",
            }:
                raise SignaturePolicyError("unsupported_cms_signature_algorithm")
            public_key.verify(
                signature,
                signed_data,
                padding.PKCS1v15(),
                digest_algorithm,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            if not signature_algorithm.endswith("_ecdsa"):
                raise SignaturePolicyError("unsupported_cms_signature_algorithm")
            public_key.verify(signature, signed_data, ec.ECDSA(digest_algorithm))
        elif isinstance(public_key, dsa.DSAPublicKey):
            if not signature_algorithm.endswith("_dsa"):
                raise SignaturePolicyError("unsupported_cms_signature_algorithm")
            public_key.verify(signature, signed_data, digest_algorithm)
        else:
            raise SignaturePolicyError("unsupported_cms_public_key_algorithm")
    except InvalidSignature as error:
        raise SignaturePolicyError("cms_signature_invalid") from error


def _require_timestamp_certificate_profile(certificate):
    try:
        basic_constraints = certificate.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
    except x509.ExtensionNotFound as error:
        raise SignaturePolicyError(
            "timestamp_certificate_missing_basic_constraints"
        ) from error
    if basic_constraints.ca:
        raise SignaturePolicyError("timestamp_certificate_is_ca")

    try:
        extended_key_usage_extension = certificate.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE
        )
    except x509.ExtensionNotFound as error:
        raise SignaturePolicyError("timestamp_certificate_missing_eku") from error
    if not extended_key_usage_extension.critical:
        raise SignaturePolicyError("timestamp_certificate_eku_not_critical")
    if set(extended_key_usage_extension.value) != {ExtendedKeyUsageOID.TIME_STAMPING}:
        raise SignaturePolicyError("timestamp_certificate_wrong_eku")

    try:
        key_usage = certificate.extensions.get_extension_for_oid(
            ExtensionOID.KEY_USAGE
        ).value
    except x509.ExtensionNotFound:
        return
    if not (key_usage.digital_signature or key_usage.content_commitment):
        raise SignaturePolicyError("timestamp_certificate_wrong_key_usage")


def _require_rfc3161_signing_certificate_attribute(
    signed_attributes,
    signer_asn1_certificate,
):
    signing_certificate_values = _cms_attribute_values(
        signed_attributes,
        SIGNING_CERTIFICATE_OID,
    )
    signing_certificate_v2_values = _cms_attribute_values(
        signed_attributes,
        SIGNING_CERTIFICATE_V2_OID,
    )
    if len(signing_certificate_values) + len(signing_certificate_v2_values) != 1:
        raise SignaturePolicyError("timestamp_signing_certificate_attribute_invalid")

    if signing_certificate_values:
        signing_certificate = signing_certificate_values[0]
        digest_algorithm_name = "sha1"
    else:
        signing_certificate = signing_certificate_v2_values[0]
        digest_algorithm_name = None
    certificate_identifiers = list(signing_certificate["certs"])
    if not certificate_identifiers:
        raise SignaturePolicyError("timestamp_signing_certificate_attribute_invalid")
    signer_identifier = certificate_identifiers[0]
    if digest_algorithm_name is None:
        digest_algorithm_name = signer_identifier["hash_algorithm"]["algorithm"].native
    expected_hash = _digest_bytes(
        signer_asn1_certificate.dump(),
        digest_algorithm_name,
    )
    if signer_identifier["cert_hash"].native != expected_hash:
        raise SignaturePolicyError("timestamp_signing_certificate_attribute_invalid")

    issuer_serial = signer_identifier["issuer_serial"]
    if issuer_serial.native is None:
        return
    if issuer_serial["serial_number"].native != signer_asn1_certificate.serial_number:
        raise SignaturePolicyError("timestamp_signing_certificate_attribute_invalid")
    directory_names = [
        general_name.chosen
        for general_name in issuer_serial["issuer"]
        if general_name.name == "directory_name"
    ]
    if len(directory_names) != 1 or (
        directory_names[0].untag().dump() != signer_asn1_certificate.issuer.dump()
    ):
        raise SignaturePolicyError("timestamp_signing_certificate_attribute_invalid")


def _verify_rfc3161_timestamp_token(
    token,
    parent_signature,
    trusted_bundle,
    *,
    budget=None,
):
    if budget is None:
        budget = SignatureVerificationBudget()
    if not isinstance(token, cms.ContentInfo):
        try:
            token = cms.ContentInfo.load(token.dump())
        except (TypeError, ValueError) as error:
            raise SignaturePolicyError("timestamp_token_parse_failed") from error
    if token["content_type"].native != "signed_data":
        raise SignaturePolicyError("timestamp_token_not_signed_data")

    signed_data = token["content"]
    signer_infos = list(signed_data["signer_infos"])
    if len(signer_infos) != 1:
        raise SignaturePolicyError("timestamp_signer_not_unique")
    signer_info = signer_infos[0]
    certificate_pairs = _cms_certificate_pairs(
        signed_data["certificates"],
        budget=budget,
    )
    signer_certificate = _find_cms_signer_certificate(
        signer_info,
        certificate_pairs,
    )
    signer_fingerprint = _certificate_fingerprint(signer_certificate)
    signer_asn1_certificates = [
        asn1_certificate
        for asn1_certificate, crypto_certificate in certificate_pairs
        if _certificate_fingerprint(crypto_certificate) == signer_fingerprint
    ]
    if len(signer_asn1_certificates) != 1:
        raise SignaturePolicyError("cms_signer_certificate_not_unique")
    signer_asn1_certificate = signer_asn1_certificates[0]

    encapsulated_content = signed_data["encap_content_info"]
    if encapsulated_content["content_type"].dotted != TST_INFO_OID:
        raise SignaturePolicyError("timestamp_content_type_invalid")
    content = encapsulated_content["content"]
    if content.native is None:
        raise SignaturePolicyError("timestamp_content_missing")
    content_bytes = content.contents

    signed_attributes = signer_info["signed_attrs"]
    content_type = _single_cms_attribute_value(
        signed_attributes,
        "1.2.840.113549.1.9.3",
        "timestamp_content_type_attribute_invalid",
    )
    if content_type.dotted != TST_INFO_OID:
        raise SignaturePolicyError("timestamp_content_type_attribute_invalid")
    message_digest = _single_cms_attribute_value(
        signed_attributes,
        "1.2.840.113549.1.9.4",
        "timestamp_message_digest_attribute_invalid",
    ).native
    digest_algorithm_name = signer_info["digest_algorithm"]["algorithm"].native
    if message_digest != _digest_bytes(content_bytes, digest_algorithm_name):
        raise SignaturePolicyError("timestamp_content_digest_mismatch")
    _require_rfc3161_signing_certificate_attribute(
        signed_attributes,
        signer_asn1_certificate,
    )
    _verify_cms_signer_signature(
        signer_info,
        signer_certificate,
        content_bytes,
    )

    try:
        timestamp_info = tsp.TSTInfo.load(content_bytes)
        generation_time = timestamp_info["gen_time"].native
        message_imprint = timestamp_info["message_imprint"]
        imprint_algorithm = message_imprint["hash_algorithm"]["algorithm"].native
        expected_imprint = _digest_bytes(parent_signature, imprint_algorithm)
    except (KeyError, TypeError, ValueError) as error:
        raise SignaturePolicyError("timestamp_info_parse_failed") from error
    if message_imprint["hashed_message"].native != expected_imprint:
        raise SignaturePolicyError("timestamp_message_imprint_mismatch")
    if generation_time.tzinfo is None:
        raise SignaturePolicyError("timestamp_generation_time_missing_timezone")
    generation_time = generation_time.astimezone(datetime.timezone.utc)

    _require_timestamp_certificate_profile(signer_certificate)
    intermediates = [
        certificate
        for _, certificate in certificate_pairs
        if _certificate_fingerprint(certificate) != signer_fingerprint
    ]
    if (
        _build_trusted_certificate_chain(
            signer_certificate,
            intermediates,
            trusted_bundle,
            generation_time,
            required_extended_key_usage=ExtendedKeyUsageOID.TIME_STAMPING,
            budget=budget,
        )
        is None
    ):
        raise SignaturePolicyError("timestamp_certificate_not_trusted")
    return generation_time


def _verify_pkcs9_countersignature(
    signer_info,
    parent_signature,
    certificate_pairs,
    trusted_bundle,
    *,
    budget=None,
):
    if budget is None:
        budget = SignatureVerificationBudget()
    signer_certificate = _find_cms_signer_certificate(
        signer_info,
        certificate_pairs,
    )
    signed_attributes = signer_info["signed_attrs"]
    if _cms_attribute_values(
        signed_attributes,
        "1.2.840.113549.1.9.3",
    ):
        raise SignaturePolicyError("countersignature_content_type_attribute_invalid")
    message_digest = _single_cms_attribute_value(
        signed_attributes,
        "1.2.840.113549.1.9.4",
        "countersignature_message_digest_attribute_invalid",
    ).native
    digest_algorithm_name = signer_info["digest_algorithm"]["algorithm"].native
    if message_digest != _digest_bytes(parent_signature, digest_algorithm_name):
        raise SignaturePolicyError("countersignature_message_digest_mismatch")
    _verify_cms_signer_signature(
        signer_info,
        signer_certificate,
        parent_signature,
    )

    signing_time_value = _single_cms_attribute_value(
        signed_attributes,
        "1.2.840.113549.1.9.5",
        "countersignature_signing_time_invalid",
    ).native
    if (
        not isinstance(signing_time_value, datetime.datetime)
        or signing_time_value.tzinfo is None
    ):
        raise SignaturePolicyError("countersignature_signing_time_invalid")
    signing_time = signing_time_value.astimezone(datetime.timezone.utc)

    _require_timestamp_certificate_profile(signer_certificate)
    intermediates = [
        certificate
        for _, certificate in certificate_pairs
        if _certificate_fingerprint(certificate)
        != _certificate_fingerprint(signer_certificate)
    ]
    if (
        _build_trusted_certificate_chain(
            signer_certificate,
            intermediates,
            trusted_bundle,
            signing_time,
            required_extended_key_usage=ExtendedKeyUsageOID.TIME_STAMPING,
            budget=budget,
        )
        is None
    ):
        raise SignaturePolicyError("countersignature_certificate_not_trusted")
    return signing_time


def _collect_signature_timestamp_entries(unsigned_attributes):
    if len(unsigned_attributes) > MAX_UNSIGNED_ATTRIBUTES_PER_SIGNER:
        raise SignaturePolicyError("unsigned_attribute_limit_exceeded")
    timestamp_entries = []
    for attribute in unsigned_attributes:
        attribute_oid = attribute["type"].dotted
        if attribute_oid == MICROSOFT_TIMESTAMP_TOKEN_OID:
            if len(attribute["values"]) == 0:
                raise SignaturePolicyError("timestamp_token_missing")
            timestamp_entries.extend(
                (attribute_oid, token) for token in attribute["values"]
            )
        elif attribute_oid == PKCS9_COUNTERSIGNATURE_OID:
            if len(attribute["values"]) == 0:
                raise SignaturePolicyError("countersignature_missing")
            timestamp_entries.extend(
                (attribute_oid, countersigner) for countersigner in attribute["values"]
            )
        if len(timestamp_entries) > MAX_TIMESTAMP_VALUES_PER_SIGNATURE:
            raise SignaturePolicyError("timestamp_value_limit_exceeded")
    unique_entries = []
    seen_entries = set()
    for attribute_oid, value in timestamp_entries:
        fingerprint = (attribute_oid, hashlib.sha256(value.dump()).digest())
        if fingerprint in seen_entries:
            continue
        seen_entries.add(fingerprint)
        unique_entries.append((attribute_oid, value))
    return unique_entries


def _verify_signature_timestamps(signature, trusted_bundle, *, budget=None):
    if budget is None:
        budget = SignatureVerificationBudget()
    raw_der = bytes(signature.raw_der)
    if len(raw_der) > MAX_SIGNATURE_DER_SIZE:
        raise SignaturePolicyError("signature_der_size_limit_exceeded")
    try:
        content_info = cms.ContentInfo.load(raw_der)
    except (TypeError, ValueError) as error:
        raise SignaturePolicyError("authenticode_cms_parse_failed") from error
    if content_info["content_type"].native != "signed_data":
        raise SignaturePolicyError("authenticode_cms_not_signed_data")

    signed_data = content_info["content"]
    signer_infos = list(signed_data["signer_infos"])
    if len(signer_infos) != 1:
        raise SignaturePolicyError("authenticode_signer_not_unique")
    signer_info = signer_infos[0]
    parent_signature = signer_info["signature"].native
    certificate_pairs = _cms_certificate_pairs(
        signed_data["certificates"],
        budget=budget,
    )

    timestamp_values = []
    unsigned_attributes = signer_info["unsigned_attrs"]
    timestamp_entries = _collect_signature_timestamp_entries(unsigned_attributes)
    for attribute_oid, value in timestamp_entries:
        if attribute_oid == MICROSOFT_TIMESTAMP_TOKEN_OID:
            timestamp_values.append(
                _verify_rfc3161_timestamp_token(
                    value,
                    parent_signature,
                    trusted_bundle,
                    budget=budget,
                )
            )
        else:
            timestamp_values.append(
                _verify_pkcs9_countersignature(
                    value,
                    parent_signature,
                    certificate_pairs,
                    trusted_bundle,
                    budget=budget,
                )
            )

    lief_timestamp_count = 0
    lief_signers = list(signature.signers)
    if len(lief_signers) > MAX_SIGNERS_PER_SIGNATURE:
        raise SignaturePolicyError("signature_signer_limit_exceeded")
    for lief_signer in lief_signers:
        unauthenticated_attributes = list(lief_signer.unauthenticated_attributes)
        if len(unauthenticated_attributes) > MAX_UNSIGNED_ATTRIBUTES_PER_SIGNER:
            raise SignaturePolicyError("unsigned_attribute_limit_exceeded")
        for attribute in unauthenticated_attributes:
            if isinstance(
                attribute,
                (lief.PE.MsCounterSign, lief.PE.PKCS9CounterSignature),
            ):
                lief_timestamp_count += 1
                if lief_timestamp_count > MAX_TIMESTAMP_VALUES_PER_SIGNATURE:
                    raise SignaturePolicyError("timestamp_value_limit_exceeded")
    if bool(lief_timestamp_count) != bool(timestamp_values):
        raise SignaturePolicyError("timestamp_parser_disagreement")
    return tuple(timestamp_values)


def _nested_authenticode_signature(attribute):
    if isinstance(attribute, lief.PE.MsSpcNestedSignature):
        return attribute.sig
    return None


def _iter_authenticode_signatures(binary):
    initial_signatures = list(binary.signatures)
    if len(initial_signatures) > MAX_AUTHENTICODE_SIGNATURES:
        raise SignaturePolicyError("signature_count_limit_exceeded")
    pending = deque((signature, 0) for signature in initial_signatures)
    seen = set()
    nested_signature_count = 0
    total_signature_der_size = 0
    while pending:
        signature, depth = pending.popleft()
        raw_der = bytes(signature.raw_der)
        if len(raw_der) > MAX_SIGNATURE_DER_SIZE:
            raise SignaturePolicyError("signature_der_size_limit_exceeded")
        fingerprint = hashlib.sha256(raw_der).digest()
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        if len(seen) > MAX_AUTHENTICODE_SIGNATURES:
            raise SignaturePolicyError("signature_count_limit_exceeded")
        total_signature_der_size += len(raw_der)
        if total_signature_der_size > MAX_TOTAL_SIGNATURE_DER_SIZE:
            raise SignaturePolicyError("signature_der_total_size_limit_exceeded")
        yield signature
        signers = list(signature.signers)
        if len(signers) > MAX_SIGNERS_PER_SIGNATURE:
            raise SignaturePolicyError("signature_signer_limit_exceeded")
        for signer in signers:
            unauthenticated_attributes = list(signer.unauthenticated_attributes)
            if len(unauthenticated_attributes) > MAX_UNSIGNED_ATTRIBUTES_PER_SIGNER:
                raise SignaturePolicyError("unsigned_attribute_limit_exceeded")
            for attribute in unauthenticated_attributes:
                nested_signature = _nested_authenticode_signature(attribute)
                if nested_signature is None:
                    continue
                if depth >= MAX_NESTED_SIGNATURE_DEPTH:
                    raise SignaturePolicyError("nested_signature_depth_limit_exceeded")
                nested_signature_count += 1
                if nested_signature_count > MAX_NESTED_SIGNATURES:
                    raise SignaturePolicyError("nested_signature_count_limit_exceeded")
                pending.append((nested_signature, depth + 1))


def _verify_authenticode_signature(
    binary,
    signature,
    trusted_bundle,
    *,
    budget=None,
):
    if budget is None:
        budget = SignatureVerificationBudget()
    signers = list(signature.signers)
    if len(signers) > MAX_SIGNERS_PER_SIGNATURE:
        raise SignaturePolicyError("signature_signer_limit_exceeded")
    if len(signers) != 1:
        raise SignaturePolicyError("authenticode_signer_not_unique")
    lief_certificates = list(signature.certificates)
    if len(lief_certificates) > MAX_EMBEDDED_CERTIFICATES_PER_SIGNATURE:
        raise SignaturePolicyError("embedded_certificate_limit_exceeded")
    if any(
        len(bytes(certificate.raw)) > MAX_CERTIFICATE_DER_SIZE
        for certificate in lief_certificates
    ):
        raise SignaturePolicyError("certificate_der_size_limit_exceeded")

    if not _lief_verification_succeeded(signature.check()):
        raise SignaturePolicyError("lief_signature_check_failed")
    if not _lief_verification_succeeded(binary.verify_signature(signature)):
        raise SignaturePolicyError("lief_authentihash_verification_failed")

    signer_certificate = signers[0].cert
    if signer_certificate is None:
        raise SignaturePolicyError("authenticode_signer_certificate_missing")
    signer_certificate = _load_cryptography_certificate(
        bytes(signer_certificate.raw),
        "authenticode_signer_certificate_parse_failed",
        budget=budget,
    )

    embedded_certificates = [
        _load_cryptography_certificate(
            bytes(certificate.raw),
            "authenticode_embedded_certificate_parse_failed",
            budget=budget,
        )
        for certificate in lief_certificates
    ]
    signer_fingerprint = _certificate_fingerprint(signer_certificate)
    if (
        sum(
            _certificate_fingerprint(certificate) == signer_fingerprint
            for certificate in embedded_certificates
        )
        != 1
    ):
        raise SignaturePolicyError("authenticode_signer_certificate_not_unique")

    if _single_common_name(signer_certificate.subject) != EXPECTED_SIGNER_CN:
        raise SignaturePolicyError("signer_common_name_mismatch")
    if _single_common_name(signer_certificate.issuer) != EXPECTED_ISSUER_CN:
        raise SignaturePolicyError("issuer_common_name_mismatch")
    _require_code_signing_certificate_profile(signer_certificate)

    timestamp_values = _verify_signature_timestamps(
        signature,
        trusted_bundle,
        budget=budget,
    )
    validation_times = timestamp_values or (
        datetime.datetime.now(datetime.timezone.utc),
    )
    intermediates = [
        certificate
        for certificate in embedded_certificates
        if _certificate_fingerprint(certificate) != signer_fingerprint
    ]
    for validation_time in validation_times:
        if (
            _build_trusted_certificate_chain(
                signer_certificate,
                intermediates,
                trusted_bundle,
                validation_time,
                required_extended_key_usage=ExtendedKeyUsageOID.CODE_SIGNING,
                budget=budget,
            )
            is None
        ):
            raise SignaturePolicyError("authenticode_signer_not_trusted")
    return True


def _log_signature_rejection(file_hash, signature_index, reason):
    print(
        "Authenticode signature rejected: "
        f"sha256={file_hash} signature={signature_index} reason={reason}",
        file=sys.stderr,
    )


def _lief_verification_succeeded(flags):
    ok_flag = lief.PE.Signature.VERIFICATION_FLAGS.OK
    if isinstance(flags, bool) or not isinstance(flags, type(ok_flag)):
        return False
    try:
        return int(flags) == int(ok_flag)
    except (TypeError, ValueError):
        return False


def verify_pe_file(file_data):
    """
    Verify PE file and extract information.

    Args:
        file_data: Bytes data of the PE file

    Returns:
        Dictionary with file_name, file_version, arch, or None if validation fails
    """
    try:
        # Parse PE file from memory
        pe = pefile.PE(data=file_data)

        # Extract FileInfo
        file_description = None
        original_filename = None
        file_version = None

        if hasattr(pe, "FileInfo") and pe.FileInfo:
            # FileInfo is a list of lists, where each inner list contains structures
            for fileinfo_list in pe.FileInfo:
                if not isinstance(fileinfo_list, list):
                    continue
                for fileinfo in fileinfo_list:
                    # Check if this structure has a Key attribute and it's StringFileInfo
                    if (
                        hasattr(fileinfo, "Key")
                        and fileinfo.Key == b"StringFileInfo"
                        and hasattr(fileinfo, "StringTable")
                        and fileinfo.StringTable
                    ):
                        for st in fileinfo.StringTable:
                            if hasattr(st, "entries") and st.entries:
                                for key, value in st.entries.items():
                                    if key == b"FileDescription":
                                        file_description = value.decode(
                                            "utf-8", errors="ignore"
                                        )
                                    elif key == b"OriginalFilename":
                                        original_filename = value.decode(
                                            "utf-8", errors="ignore"
                                        )
                                    elif key == b"FileVersion":
                                        file_version = value.decode(
                                            "utf-8", errors="ignore"
                                        )

        # Verify FileDescription is in allowed list
        if file_description not in ALLOW_FILEDESC:
            return None

        # Check required fields
        if not original_filename or not file_version:
            return None

        # Verify OriginalFilename is in allowed list
        if original_filename.lower() not in [name.lower() for name in ALLOW_FILENAME]:
            return None

        # Normalize filename: if OriginalFilename is ntkrnlmp.exe, use ntoskrnl.exe
        if original_filename.lower() == "ntkrnlmp.exe":
            original_filename = "ntoskrnl.exe"

        # Clean file version: remove content in parentheses if present
        # Example: "10.0.26100.7462 (WinBuild.160101.0800)" -> "10.0.26100.7462"
        if "(" in file_version:
            file_version = file_version.split("(")[0].strip()

        # Determine architecture
        machine = pe.FILE_HEADER.Machine
        if machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]:
            arch = "x86"
        elif machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
            arch = "amd64"
        elif machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_ARM64"]:
            arch = "arm64"
        else:
            return None

        pe.close()

        return {
            "file_name": original_filename,
            "file_version": file_version,
            "arch": arch,
        }

    except pefile.PEFormatError:
        return None
    except Exception as error:  # noqa: BLE001 - all parser failures fail closed.
        file_hash = hashlib.sha256(file_data).hexdigest()
        print(
            "PE parsing rejected: "
            f"sha256={file_hash} "
            f"reason=pe_parse_exception_{type(error).__name__}",
            file=sys.stderr,
        )
        return None


def _preflight_pe_certificate_table(file_data):
    """Bound the PE certificate table before invoking LIEF's native parser."""
    if len(file_data) < 0x40 or file_data[:2] != b"MZ":
        raise SignaturePolicyError("pe_header_invalid")
    pe_offset = int.from_bytes(file_data[0x3C:0x40], "little")
    if (
        pe_offset + 24 > len(file_data)
        or file_data[pe_offset : pe_offset + 4] != b"PE\0\0"
    ):
        raise SignaturePolicyError("pe_header_invalid")

    optional_header_size = int.from_bytes(
        file_data[pe_offset + 20 : pe_offset + 22],
        "little",
    )
    optional_header_offset = pe_offset + 24
    optional_header_end = optional_header_offset + optional_header_size
    if optional_header_end > len(file_data) or optional_header_size < 2:
        raise SignaturePolicyError("pe_optional_header_invalid")

    optional_header_magic = int.from_bytes(
        file_data[optional_header_offset : optional_header_offset + 2],
        "little",
    )
    if optional_header_magic == 0x10B:
        data_directory_offset = optional_header_offset + 96
        directory_count_offset = optional_header_offset + 92
    elif optional_header_magic == 0x20B:
        data_directory_offset = optional_header_offset + 112
        directory_count_offset = optional_header_offset + 108
    else:
        raise SignaturePolicyError("pe_optional_header_invalid")

    if directory_count_offset + 4 > optional_header_end:
        raise SignaturePolicyError("pe_optional_header_invalid")
    directory_count = int.from_bytes(
        file_data[directory_count_offset : directory_count_offset + 4],
        "little",
    )
    if directory_count <= 4:
        return 0
    security_directory_offset = data_directory_offset + (4 * 8)
    if security_directory_offset + 8 > optional_header_end:
        raise SignaturePolicyError("pe_security_directory_invalid")

    certificate_table_offset = int.from_bytes(
        file_data[security_directory_offset : security_directory_offset + 4],
        "little",
    )
    certificate_table_size = int.from_bytes(
        file_data[security_directory_offset + 4 : security_directory_offset + 8],
        "little",
    )
    if certificate_table_offset == 0 and certificate_table_size == 0:
        return 0
    if certificate_table_offset == 0 or certificate_table_size == 0:
        raise SignaturePolicyError("pe_security_directory_invalid")
    if certificate_table_size > MAX_PE_CERTIFICATE_TABLE_SIZE:
        raise SignaturePolicyError("pe_certificate_table_size_limit_exceeded")
    certificate_table_end = certificate_table_offset + certificate_table_size
    if certificate_table_end > len(file_data):
        raise SignaturePolicyError("pe_certificate_table_truncated")

    certificate_count = 0
    cursor = certificate_table_offset
    while cursor < certificate_table_end:
        if cursor + 8 > certificate_table_end:
            raise SignaturePolicyError("win_certificate_header_truncated")
        certificate_length = int.from_bytes(file_data[cursor : cursor + 4], "little")
        if certificate_length < 8:
            raise SignaturePolicyError("win_certificate_length_invalid")
        if certificate_length - 8 > MAX_SIGNATURE_DER_SIZE:
            raise SignaturePolicyError("signature_der_size_limit_exceeded")
        record_end = cursor + certificate_length
        if record_end > certificate_table_end:
            raise SignaturePolicyError("win_certificate_truncated")
        certificate_count += 1
        if certificate_count > MAX_AUTHENTICODE_SIGNATURES:
            raise SignaturePolicyError("signature_count_limit_exceeded")
        cursor = (record_end + 7) & ~7
        if cursor > certificate_table_end:
            if record_end == certificate_table_end:
                cursor = certificate_table_end
            else:
                raise SignaturePolicyError("win_certificate_alignment_invalid")
    return certificate_count


def verify_signature(file_data):
    """
    Verify Authenticode digital signature.

    Args:
        file_data: Bytes data of the PE file

    Returns:
        True if signature is valid and matches requirements, False otherwise
    """
    trusted_bundle = _WINDOWS_CODE_SIGNING_CA_BUNDLE
    file_hash = hashlib.sha256(file_data).hexdigest()
    if trusted_bundle is None:
        _log_signature_rejection(file_hash, "none", "ca_preflight_not_completed")
        return False

    try:
        certificate_count = _preflight_pe_certificate_table(file_data)
    except SignaturePolicyError as error:
        _log_signature_rejection(file_hash, "none", str(error))
        return False
    except Exception as error:  # noqa: BLE001 - preflight must fail closed.
        _log_signature_rejection(
            file_hash,
            "none",
            f"pe_preflight_exception_{type(error).__name__}",
        )
        return False
    if certificate_count == 0:
        _log_signature_rejection(file_hash, "none", "no_authenticode_signature")
        return False

    try:
        binary = lief.PE.parse(file_data)
    except Exception as error:  # noqa: BLE001 - LIEF may raise native exceptions.
        _log_signature_rejection(
            file_hash,
            "none",
            f"lief_parse_exception_{type(error).__name__}",
        )
        return False
    if binary is None:
        _log_signature_rejection(file_hash, "none", "lief_parse_failed")
        return False

    try:
        signatures = list(_iter_authenticode_signatures(binary))
    except SignaturePolicyError as error:
        _log_signature_rejection(file_hash, "none", str(error))
        return False
    except Exception as error:  # noqa: BLE001 - enumeration must fail closed.
        _log_signature_rejection(
            file_hash,
            "none",
            f"signature_enumeration_exception_{type(error).__name__}",
        )
        return False
    if not signatures:
        _log_signature_rejection(file_hash, "none", "no_authenticode_signature")
        return False

    budget = SignatureVerificationBudget()
    for signature_index, signature in enumerate(signatures):
        try:
            if _verify_authenticode_signature(
                binary,
                signature,
                trusted_bundle,
                budget=budget,
            ):
                return True
        except SignaturePolicyError as error:
            _log_signature_rejection(
                file_hash,
                signature_index,
                str(error),
            )
        except Exception as error:  # noqa: BLE001 - per-signature fail closed.
            _log_signature_rejection(
                file_hash,
                signature_index,
                f"verification_exception_{type(error).__name__}",
            )
    return False


def save_file(file_data, file_name, file_version, arch, storage):
    """
    Save file to target directory.

    Args:
        file_data: Bytes data of the file
        file_name: Original filename
        file_version: File version
        arch: Architecture (x86/amd64/arm64)
        storage: Configured storage backend

    Returns:
        Tuple of (success: bool, message: str, status_code: int, sha256: str or None)
    """
    # Calculate SHA256 hash of the file
    file_hash = hashlib.sha256(file_data).hexdigest().lower()

    relative_path = build_symbol_path(
        arch,
        file_name,
        file_version,
        file_hash,
    )
    success, message, status_code = storage.save_file(
        relative_path,
        file_data,
        file_hash,
    )
    return (success, message, status_code, file_hash)


class UploadHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for file uploads."""

    def __init__(self, *args, storage=None, debug=False, **kwargs):
        self.storage = storage
        self.debug = debug
        super().__init__(*args, **kwargs)

    def send_json_response(self, status_code, message, data=None):
        """
        Send JSON response.

        Args:
            status_code: HTTP status code
            message: Response message
            data: Optional additional data dictionary
        """
        response = {"success": 200 <= status_code < 300, "message": message}
        if data:
            response.update(data)

        response_json = json.dumps(response, ensure_ascii=False)

        try:
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(response_json.encode("utf-8"))
        except (ConnectionResetError, BrokenPipeError):
            # 客户端已断开连接，忽略
            pass

    def send_error(self, code, message=None, explain=None):
        """
        Override send_error to return JSON instead of HTML.

        Args:
            code: HTTP status code
            message: Error message
            explain: Additional explanation (ignored, message is used instead)
        """
        if message is None:
            # Default messages for common status codes
            messages = {
                400: "Bad Request",
                401: "Unauthorized",
                403: "Forbidden",
                404: "Not Found",
                405: "Method Not Allowed",
                500: "Internal Server Error",
                501: "Not Implemented",
                502: "Bad Gateway",
                503: "Service Unavailable",
            }
            message = messages.get(code, f"Error {code}")

        self.send_json_response(code, message)

    def do_GET(self):
        """Handle GET requests to /health and /exists."""
        parsed_url = urlparse(self.path)
        path = parsed_url.path

        # Handle health check endpoint
        if path == "/health":
            self.send_json_response(200, "OK", {"status": "healthy"})
            return

        if path == "/":
            self.send_json_response(200, "OK", {"status": "healthy"})
            return

        # Handle file existence check endpoint
        if path != "/exists":
            self.send_json_response(404, "Not Found")
            return

        # Parse query parameters
        query_params = parse_qs(parsed_url.query)

        # Get required parameters
        filename = query_params.get("filename", [None])[0]
        arch = query_params.get("arch", [None])[0]
        fileversion = query_params.get("fileversion", [None])[0]
        sha256 = query_params.get("sha256", [None])[0]

        # Validate required parameters
        if not filename or not arch or not fileversion or not sha256:
            self.send_json_response(
                400,
                "Missing required parameters: filename, arch, fileversion, and sha256 are required",
            )
            return

        # Normalize sha256 to lowercase
        sha256 = sha256.lower()

        # Validate parameter values
        is_valid, error_message = validate_exists_params(
            arch, filename, fileversion, sha256
        )
        if not is_valid:
            self.send_json_response(400, error_message)
            return

        # Check file existence
        try:
            response_data = check_file_exists(
                self.storage,
                arch,
                filename,
                fileversion,
                sha256,
            )
        except StorageError as error:
            self.send_json_response(502, str(error))
            return

        self.send_json_response(200, "File existence checked", response_data)

    def do_HEAD(self):
        """Handle HEAD requests for health checks."""
        parsed_url = urlparse(self.path)
        path = parsed_url.path

        if path in ("/health", "/"):
            # HEAD must not send a message body; only headers.
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        """Handle POST requests to /upload."""
        if self.path != "/upload":
            self.send_json_response(404, "Not Found")
            return

        # Check content length
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            self.send_json_response(400, "Invalid Content-Length")
            return

        if content_length > MAX_FILE_SIZE:
            self.send_json_response(
                413, f"File too large (max {MAX_FILE_SIZE / (1024 * 1024)}MB)"
            )
            return

        if content_length == 0:
            self.send_json_response(400, "No file data")
            return

        # Check Content-Type and handle accordingly
        content_type = self.headers.get("Content-Type", "").lower()

        # Only accept application/octet-stream or empty Content-Type
        if not (
            content_type.startswith("application/octet-stream") or content_type == ""
        ):
            self.send_json_response(
                400, "Content-Type must be application/octet-stream"
            )
            return

        # Read file data directly from request body
        try:
            file_data = self.rfile.read(content_length)
        except Exception as error:  # noqa: BLE001 - request stream errors vary.
            print(
                f"Upload body read failed: reason={type(error).__name__}",
                file=sys.stderr,
            )
            self.send_json_response(400, "Failed to read file data")
            return

        # Verify file size does not exceed maximum allowed size (compressed size)
        if len(file_data) > MAX_FILE_SIZE:
            self.send_json_response(
                413, f"File too large (max {MAX_FILE_SIZE / (1024 * 1024)}MB)"
            )
            return

        # Handle optional gzip compression indicated by header
        compression_type = self.headers.get("X-File-Compressed", "").strip().lower()
        if compression_type == "gzip":
            try:
                file_data = gzip.decompress(file_data)
            except OSError as e:
                self.send_json_response(400, f"Failed to decompress gzip data: {e}")
                return

            # Check decompressed size as well
            if len(file_data) > MAX_FILE_SIZE:
                self.send_json_response(
                    413,
                    f"Decompressed file too large (max {MAX_FILE_SIZE / (1024 * 1024)}MB)",
                )
                return

        # Verify PE file and extract information
        pe_info = verify_pe_file(file_data)
        if not pe_info:
            self.send_json_response(
                400,
                "Invalid PE file or FileDescription does not match 'NT Kernel & System'",
            )
            return

        # Verify digital signature
        if not verify_signature(file_data):
            self.send_json_response(
                400,
                "Digital signature verification failed or does not match requirements",
            )
            return

        # Save file
        try:
            success, message, status_code, file_hash = save_file(
                file_data,
                pe_info["file_name"],
                pe_info["file_version"],
                pe_info["arch"],
                self.storage,
            )
        except StorageError as error:
            self.send_json_response(502, str(error))
            return

        if success:
            self.send_json_response(
                status_code,
                message,
                {
                    "file_name": pe_info["file_name"],
                    "file_version": pe_info["file_version"],
                    "arch": pe_info["arch"],
                    "sha256": file_hash,
                },
            )
        else:
            self.send_json_response(status_code, message)

    def log_message(self, format, *args):
        """Override to customize log format."""
        if not self.debug:
            return
        message = format.__mod__(args)
        sys.stderr.write(
            f"{self.address_string()} - - [{self.log_date_time_string()}] {message}\n"
        )


def main():
    """Main entry point."""
    load_dotenv(dotenv_path=Path(__file__).resolve().with_name(".env"), override=False)
    args = parse_args()

    try:
        preflight_windows_code_signing_ca_bundle()
    except CertificateBundleError as error:
        print(f"Error: {error}")
        sys.exit(1)

    try:
        storage_mode = get_storage_mode()
    except ValueError as error:
        print(f"Error: {error}")
        sys.exit(1)

    # Get port from environment variable or command line argument
    port_env = os.environ.get("KPHTOOLS_SERVER_PORT")
    if port_env:
        try:
            port = int(port_env)
        except ValueError:
            print(
                f"Error: Invalid KPHTOOLS_SERVER_PORT environment variable value: {port_env}"
            )
            sys.exit(1)
    else:
        port = args.port

    symboldir = args.symboldir
    try:
        storage = create_storage_backend(storage_mode, symboldir=symboldir)
    except (ValueError, RuntimeError, OSError) as error:
        print(f"Error: {error}")
        sys.exit(1)

    print(f"Storage mode: {storage_mode}")
    if storage_mode == "disk":
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        print(f"Symbol directory: {storage.symboldir}")
        print(f"Upload directory: {UPLOAD_DIR}")
    else:
        print(f"OSS region: {os.environ['KPHTOOLS_SERVER_OSS_REGION'].strip()}")
        print(f"OSS bucket: {storage.bucket}")
        print(f"OSS prefix: {storage.prefix or '(none)'}")

    print(f"Max file size: {MAX_FILE_SIZE / (1024 * 1024)}MB")
    print(f"Starting server on port {port}...")
    print(f"Upload endpoint: http://localhost:{port}/upload")

    # Create handler with storage backend parameter
    def handler_factory(*handler_args, **handler_kwargs):
        return UploadHandler(
            *handler_args,
            storage=storage,
            debug=args.debug,
            **handler_kwargs,
        )

    # Start server
    try:
        with ThreadedHTTPServer(("", port), handler_factory) as httpd:
            print("Server started. Press Ctrl+C to stop.")
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    except OSError as e:
        print(f"Error: Failed to start server: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
