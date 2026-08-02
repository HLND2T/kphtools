import base64
import datetime
import hashlib
import os
import tempfile
import unittest
from io import BytesIO, StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import alibabacloud_oss_v2 as real_oss
from asn1crypto import cms, tsp
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import upload_server


class FakeServiceError(Exception):
    def __init__(self, status_code, code, request_id="request-id"):
        super().__init__(code)
        self.status_code = status_code
        self.code = code
        self.request_id = request_id


class FakeRequest:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class FakeCredentialsProvider:
    pass


class FakeConfig:
    def __init__(self):
        self.credentials_provider = None
        self.region = None
        self.endpoint = None


class FakeClient:
    def __init__(self, config):
        self.config = config


class FakeOssModule:
    HeadObjectRequest = FakeRequest
    PutObjectRequest = FakeRequest
    Client = FakeClient
    exceptions = SimpleNamespace(ServiceError=FakeServiceError)
    credentials = SimpleNamespace(
        EnvironmentVariableCredentialsProvider=FakeCredentialsProvider
    )
    config = SimpleNamespace(load_default=FakeConfig)


class RecordingStorage:
    def __init__(self, exists=False, file_size=None):
        self.exists = exists
        self.file_size = file_size
        self.saved = []

    def stat_file(self, relative_path):
        self.stat_path = relative_path
        return self.exists, self.file_size

    def save_file(self, relative_path, file_data, file_hash):
        self.saved.append((relative_path, file_data, file_hash))
        return True, "File uploaded successfully", 200


TEST_TIME = datetime.datetime(2026, 7, 27, 0, 0, tzinfo=datetime.timezone.utc)


def make_name(*common_names):
    attributes = [x509.NameAttribute(NameOID.COUNTRY_NAME, "US")]
    attributes.extend(
        x509.NameAttribute(NameOID.COMMON_NAME, common_name)
        for common_name in common_names
    )
    return x509.Name(attributes)


def make_certificate(
    *,
    subject,
    issuer,
    public_key,
    issuer_key,
    is_ca,
    not_valid_before=None,
    not_valid_after=None,
    extended_key_usage=None,
    extended_key_usage_critical=True,
    include_basic_constraints=True,
    path_length=None,
    key_usage=None,
    extra_extensions=(),
):
    not_valid_before = not_valid_before or (TEST_TIME - datetime.timedelta(days=1))
    not_valid_after = not_valid_after or (TEST_TIME + datetime.timedelta(days=365))
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
    )
    if include_basic_constraints:
        builder = builder.add_extension(
            x509.BasicConstraints(
                ca=is_ca,
                path_length=path_length if is_ca else None,
            ),
            critical=True,
        )
    if is_ca and key_usage is None:
        key_usage = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        )
    if key_usage is not None:
        builder = builder.add_extension(key_usage, critical=True)
    if extended_key_usage is not None:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(extended_key_usage),
            critical=extended_key_usage_critical,
        )
    for extension, critical in extra_extensions:
        builder = builder.add_extension(extension, critical=critical)
    return builder.sign(issuer_key, hashes.SHA256())


def make_test_chain(
    *,
    signer_common_names=(upload_server.EXPECTED_SIGNER_CN,),
    issuer_common_name=upload_server.EXPECTED_ISSUER_CN,
    leaf_not_valid_before=None,
    leaf_not_valid_after=None,
    leaf_is_ca=False,
    leaf_extended_key_usage=(ExtendedKeyUsageOID.CODE_SIGNING,),
    leaf_include_basic_constraints=True,
    leaf_key_usage=None,
    intermediate_path_length=None,
    intermediate_extended_key_usage=None,
    intermediate_extra_extensions=(),
    root_path_length=None,
):
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = make_name("Test Root CA")
    root_certificate = make_certificate(
        subject=root_name,
        issuer=root_name,
        public_key=root_key.public_key(),
        issuer_key=root_key,
        is_ca=True,
        path_length=root_path_length,
    )

    intermediate_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    intermediate_name = make_name(issuer_common_name)
    intermediate_certificate = make_certificate(
        subject=intermediate_name,
        issuer=root_name,
        public_key=intermediate_key.public_key(),
        issuer_key=root_key,
        is_ca=True,
        path_length=intermediate_path_length,
        extended_key_usage=intermediate_extended_key_usage,
        extra_extensions=intermediate_extra_extensions,
    )

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_name = make_name(*signer_common_names)
    leaf_certificate = make_certificate(
        subject=leaf_name,
        issuer=intermediate_name,
        public_key=leaf_key.public_key(),
        issuer_key=intermediate_key,
        is_ca=leaf_is_ca,
        not_valid_before=leaf_not_valid_before,
        not_valid_after=leaf_not_valid_after,
        extended_key_usage=leaf_extended_key_usage,
        include_basic_constraints=leaf_include_basic_constraints,
        key_usage=leaf_key_usage,
    )
    return SimpleNamespace(
        root_key=root_key,
        root=root_certificate,
        intermediate_key=intermediate_key,
        intermediate=intermediate_certificate,
        leaf_key=leaf_key,
        leaf=leaf_certificate,
    )


def make_bundle(*certificates):
    return upload_server.TrustedCertificateBundle(
        path=upload_server.WINDOWS_CODE_SIGNING_CA_PATH,
        certificates=tuple(certificates),
        sha256="0" * 64,
        block_count=len(certificates),
        duplicate_count=0,
    )


def certificate_pem(certificate):
    return certificate.public_bytes(serialization.Encoding.PEM)


def non_signing_key_usage():
    return x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=True,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )


def build_rfc3161_timestamp_token(
    parent_signature,
    *,
    generation_time=TEST_TIME,
    message_imprint=None,
    timestamp_eku=True,
    timestamp_eku_oids=None,
    timestamp_eku_critical=True,
    timestamp_is_ca=False,
    timestamp_key_usage=None,
    include_signing_certificate=True,
    signing_certificate_hash=None,
):
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = make_name("Timestamp Root CA")
    root_certificate = make_certificate(
        subject=root_name,
        issuer=root_name,
        public_key=root_key.public_key(),
        issuer_key=root_key,
        is_ca=True,
    )

    timestamp_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    timestamp_name = make_name("Timestamp Service")
    timestamp_certificate = make_certificate(
        subject=timestamp_name,
        issuer=root_name,
        public_key=timestamp_key.public_key(),
        issuer_key=root_key,
        is_ca=timestamp_is_ca,
        extended_key_usage=(
            timestamp_eku_oids
            if timestamp_eku_oids is not None
            else ([ExtendedKeyUsageOID.TIME_STAMPING] if timestamp_eku else None)
        ),
        extended_key_usage_critical=timestamp_eku_critical,
        key_usage=timestamp_key_usage,
    )
    timestamp_certificate_der = timestamp_certificate.public_bytes(
        serialization.Encoding.DER
    )
    asn1_timestamp_certificate = asn1_x509.Certificate.load(timestamp_certificate_der)
    asn1_root_certificate = asn1_x509.Certificate.load(
        root_certificate.public_bytes(serialization.Encoding.DER)
    )

    if message_imprint is None:
        message_imprint = hashlib.sha256(parent_signature).digest()
    timestamp_info = tsp.TSTInfo(
        {
            "version": "v1",
            "policy": "1.2.3.4",
            "message_imprint": {
                "hash_algorithm": {"algorithm": "sha256"},
                "hashed_message": message_imprint,
            },
            "serial_number": 1,
            "gen_time": generation_time,
        }
    )
    content_bytes = timestamp_info.dump()
    signed_attribute_values = [
        {"type": "content_type", "values": ["tst_info"]},
        {
            "type": "message_digest",
            "values": [hashlib.sha256(content_bytes).digest()],
        },
    ]
    if include_signing_certificate:
        if signing_certificate_hash is None:
            signing_certificate_hash = hashlib.sha256(
                timestamp_certificate_der
            ).digest()
        signing_certificate_v2 = tsp.SigningCertificateV2(
            {
                "certs": [
                    {
                        "hash_algorithm": {"algorithm": "sha256"},
                        "cert_hash": signing_certificate_hash,
                        "issuer_serial": {
                            "issuer": [
                                asn1_x509.GeneralName(
                                    {
                                        "directory_name": asn1_timestamp_certificate.issuer
                                    }
                                )
                            ],
                            "serial_number": asn1_timestamp_certificate.serial_number,
                        },
                    }
                ]
            }
        )
        signed_attribute_values.append(
            {
                "type": "signing_certificate_v2",
                "values": [signing_certificate_v2],
            }
        )
    signed_attributes = cms.CMSAttributes(signed_attribute_values)
    signature = timestamp_key.sign(
        signed_attributes.dump(),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    signer_info = cms.SignerInfo(
        {
            "version": "v1",
            "sid": {
                "issuer_and_serial_number": {
                    "issuer": asn1_timestamp_certificate.issuer,
                    "serial_number": asn1_timestamp_certificate.serial_number,
                }
            },
            "digest_algorithm": {"algorithm": "sha256"},
            "signed_attrs": signed_attributes,
            "signature_algorithm": {"algorithm": "rsassa_pkcs1v15"},
            "signature": signature,
        }
    )
    signed_data = cms.SignedData(
        {
            "version": "v3",
            "digest_algorithms": [{"algorithm": "sha256"}],
            "encap_content_info": {
                "content_type": "tst_info",
                "content": timestamp_info,
            },
            "certificates": [
                asn1_timestamp_certificate,
                asn1_root_certificate,
            ],
            "signer_infos": [signer_info],
        }
    )
    token = cms.ContentInfo({"content_type": "signed_data", "content": signed_data})
    return SimpleNamespace(
        token=token,
        root=root_certificate,
        timestamp_certificate=timestamp_certificate,
    )


def build_pkcs9_countersignature(
    parent_signature,
    *,
    include_content_type=False,
    duplicate_message_digest=False,
):
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = make_name("Countersignature Root CA")
    root_certificate = make_certificate(
        subject=root_name,
        issuer=root_name,
        public_key=root_key.public_key(),
        issuer_key=root_key,
        is_ca=True,
    )

    timestamp_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    timestamp_name = make_name("Countersignature Service")
    timestamp_certificate = make_certificate(
        subject=timestamp_name,
        issuer=root_name,
        public_key=timestamp_key.public_key(),
        issuer_key=root_key,
        is_ca=False,
        extended_key_usage=[ExtendedKeyUsageOID.TIME_STAMPING],
    )

    message_digest_attribute = {
        "type": "message_digest",
        "values": [hashlib.sha256(parent_signature).digest()],
    }
    attributes = [
        message_digest_attribute,
        {
            "type": "signing_time",
            "values": [cms.Time({"utc_time": TEST_TIME})],
        },
    ]
    if duplicate_message_digest:
        attributes.append(message_digest_attribute)
    if include_content_type:
        attributes.append({"type": "content_type", "values": ["data"]})
    signed_attributes = cms.CMSAttributes(attributes)
    signature = timestamp_key.sign(
        signed_attributes.dump(),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    asn1_timestamp_certificate = asn1_x509.Certificate.load(
        timestamp_certificate.public_bytes(serialization.Encoding.DER)
    )
    asn1_root_certificate = asn1_x509.Certificate.load(
        root_certificate.public_bytes(serialization.Encoding.DER)
    )
    signer_info = cms.SignerInfo(
        {
            "version": "v1",
            "sid": {
                "issuer_and_serial_number": {
                    "issuer": asn1_timestamp_certificate.issuer,
                    "serial_number": asn1_timestamp_certificate.serial_number,
                }
            },
            "digest_algorithm": {"algorithm": "sha256"},
            "signed_attrs": signed_attributes,
            "signature_algorithm": {"algorithm": "rsassa_pkcs1v15"},
            "signature": signature,
        }
    )
    return SimpleNamespace(
        signer_info=signer_info,
        root=root_certificate,
        certificate_pairs=[
            (asn1_timestamp_certificate, timestamp_certificate),
            (asn1_root_certificate, root_certificate),
        ],
    )


class FakeLiefCertificate:
    def __init__(self, certificate):
        self.raw = certificate.public_bytes(serialization.Encoding.DER)


class TestDotenvLoading(unittest.TestCase):
    def test_main_loads_dotenv_before_parsing_arguments(self):
        events = []

        def load_dotenv(**_kwargs):
            events.append("dotenv")

        def parse_arguments():
            events.append("arguments")
            raise RuntimeError("stop after argument parsing")

        with (
            patch.object(upload_server, "load_dotenv", side_effect=load_dotenv) as dotenv_loader,
            patch.object(upload_server, "parse_args", side_effect=parse_arguments),
            self.assertRaisesRegex(RuntimeError, "stop after argument parsing"),
        ):
            upload_server.main()

        self.assertEqual(["dotenv", "arguments"], events)
        dotenv_loader.assert_called_once_with(
            dotenv_path=Path(upload_server.__file__).resolve().with_name(".env"),
            override=False,
        )

    def test_main_stops_before_storage_when_ca_preflight_fails(self):
        with (
            patch.object(upload_server, "load_dotenv"),
            patch.object(
                upload_server,
                "parse_args",
                return_value=SimpleNamespace(
                    symboldir="symbols",
                    port=8000,
                    debug=False,
                ),
            ),
            patch.object(
                upload_server,
                "preflight_windows_code_signing_ca_bundle",
                side_effect=upload_server.CertificateBundleError("bundle failed"),
            ),
            patch.object(upload_server, "create_storage_backend") as create_storage,
            patch.object(upload_server, "ThreadedHTTPServer") as server_type,
            patch("sys.stdout", new_callable=StringIO),
            self.assertRaises(SystemExit) as exit_context,
        ):
            upload_server.main()

        self.assertEqual(1, exit_context.exception.code)
        create_storage.assert_not_called()
        server_type.assert_not_called()


class TestCodeSigningCertificateBundle(unittest.TestCase):
    def test_repository_bundle_parses_all_blocks_and_deduplicates(self):
        bundle = upload_server.load_windows_code_signing_ca_bundle()

        self.assertEqual(upload_server.WINDOWS_CODE_SIGNING_CA_PATH, bundle.path)
        self.assertEqual(82, bundle.block_count)
        self.assertEqual(46, len(bundle.certificates))
        self.assertEqual(36, bundle.duplicate_count)
        self.assertEqual(
            "4C0BAB3E51710D7A78B7F24166EA3BD69AC70828697E6946945E391E57F7943E",
            bundle.sha256,
        )

    def test_loader_uses_script_relative_path_outside_repository_cwd(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_cwd = Path.cwd()
            try:
                os.chdir(temp_dir)
                bundle = upload_server.load_windows_code_signing_ca_bundle()
            finally:
                os.chdir(original_cwd)

        self.assertEqual(upload_server.WINDOWS_CODE_SIGNING_CA_PATH, bundle.path)

    def test_loader_reports_missing_file_without_certificate_content(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            missing_path = Path(temp_dir) / "missing.pem"
            with (
                patch.object(
                    upload_server,
                    "WINDOWS_CODE_SIGNING_CA_PATH",
                    missing_path,
                ),
                self.assertRaisesRegex(
                    upload_server.CertificateBundleError,
                    "FileNotFoundError",
                ) as error_context,
            ):
                upload_server.load_windows_code_signing_ca_bundle()

        self.assertIn(str(missing_path), str(error_context.exception))

    def test_parser_deduplicates_certificates_by_der_fingerprint(self):
        chain = make_test_chain()
        pem = certificate_pem(chain.root)
        bundle = upload_server._parse_certificate_bundle(
            pem + pem,
            "duplicate.pem",
        )

        self.assertEqual(2, bundle.block_count)
        self.assertEqual(1, len(bundle.certificates))
        self.assertEqual(1, bundle.duplicate_count)

    def test_parser_rejects_empty_and_malformed_bundles(self):
        invalid_bundles = {
            "empty": b"",
            "zero-certificates": b"subject=example\nissuer=example\n",
            "truncated": b"-----BEGIN CERTIFICATE-----\nAAAA\n",
            "non-certificate": (
                b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
            ),
            "invalid-base64": (
                b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n"
            ),
            "invalid-der": (
                b"-----BEGIN CERTIFICATE-----\n"
                + base64.b64encode(b"not a certificate")
                + b"\n-----END CERTIFICATE-----\n"
            ),
        }

        for name, raw_data in invalid_bundles.items():
            with self.subTest(name=name):
                with self.assertRaises(upload_server.CertificateBundleError) as context:
                    upload_server._parse_certificate_bundle(raw_data, f"{name}.pem")
                self.assertNotIn("not a certificate", str(context.exception))


class TestCertificateTrustPolicy(unittest.TestCase):
    def test_valid_embedded_intermediate_chains_to_bundle_anchor(self):
        chain = make_test_chain()

        result = upload_server._build_trusted_certificate_chain(
            chain.leaf,
            [chain.intermediate],
            make_bundle(chain.root),
            TEST_TIME,
        )

        self.assertIsNotNone(result)
        self.assertEqual(
            [chain.leaf, chain.intermediate, chain.root],
            list(result),
        )

    def test_unknown_root_and_embedded_self_signed_root_are_not_trusted(self):
        chain = make_test_chain()
        other_chain = make_test_chain()

        result = upload_server._build_trusted_certificate_chain(
            chain.leaf,
            [chain.intermediate, chain.root],
            make_bundle(other_chain.root),
            TEST_TIME,
        )

        self.assertIsNone(result)

    def test_missing_intermediate_is_rejected(self):
        chain = make_test_chain()

        result = upload_server._build_trusted_certificate_chain(
            chain.leaf,
            [],
            make_bundle(chain.root),
            TEST_TIME,
        )

        self.assertIsNone(result)

    def test_bundle_only_root_can_trust_a_non_system_chain(self):
        chain = make_test_chain()

        self.assertIsNotNone(
            upload_server._build_trusted_certificate_chain(
                chain.leaf,
                [chain.intermediate],
                make_bundle(chain.root),
                TEST_TIME,
            )
        )
        self.assertIsNone(
            upload_server._build_trusted_certificate_chain(
                chain.leaf,
                [chain.intermediate],
                make_bundle(),
                TEST_TIME,
            )
        )

    def test_historical_validation_time_accepts_timestamped_expired_leaf(self):
        historical_time = TEST_TIME - datetime.timedelta(hours=12)
        chain = make_test_chain(
            leaf_not_valid_before=historical_time - datetime.timedelta(days=1),
            leaf_not_valid_after=TEST_TIME - datetime.timedelta(hours=1),
        )
        bundle = make_bundle(chain.root)

        self.assertIsNotNone(
            upload_server._build_trusted_certificate_chain(
                chain.leaf,
                [chain.intermediate],
                bundle,
                historical_time,
            )
        )
        self.assertIsNone(
            upload_server._build_trusted_certificate_chain(
                chain.leaf,
                [chain.intermediate],
                bundle,
                TEST_TIME,
            )
        )

    def test_path_length_constraint_is_enforced(self):
        chain = make_test_chain(root_path_length=0)

        self.assertIsNone(
            upload_server._build_trusted_certificate_chain(
                chain.leaf,
                [chain.intermediate],
                make_bundle(chain.root),
                TEST_TIME,
            )
        )

    def test_chain_candidate_and_search_limits_fail_closed(self):
        chain = make_test_chain()
        with (
            patch.object(upload_server, "MAX_CERTIFICATE_CHAIN_CANDIDATES", 1),
            self.assertRaisesRegex(
                upload_server.SignaturePolicyError,
                "certificate_chain_candidate_limit_exceeded",
            ),
        ):
            upload_server._build_trusted_certificate_chain(
                chain.leaf,
                [chain.intermediate],
                make_bundle(chain.root),
                TEST_TIME,
            )

        with (
            patch.object(upload_server, "MAX_CERTIFICATE_CHAIN_SEARCH_STATES", 1),
            self.assertRaisesRegex(
                upload_server.SignaturePolicyError,
                "certificate_chain_search_limit_exceeded",
            ),
        ):
            upload_server._build_trusted_certificate_chain(
                chain.leaf,
                [chain.intermediate],
                make_bundle(chain.root),
                TEST_TIME,
            )

    def test_chain_budget_and_cache_are_shared(self):
        chain = make_test_chain()
        budget = upload_server.SignatureVerificationBudget()
        first_result = upload_server._build_trusted_certificate_chain(
            chain.leaf,
            [chain.intermediate],
            make_bundle(chain.root),
            TEST_TIME,
            required_extended_key_usage=ExtendedKeyUsageOID.CODE_SIGNING,
            budget=budget,
        )
        remaining_edges = budget.remaining_edge_verifications

        second_result = upload_server._build_trusted_certificate_chain(
            chain.leaf,
            [chain.intermediate],
            make_bundle(chain.root),
            TEST_TIME,
            required_extended_key_usage=ExtendedKeyUsageOID.CODE_SIGNING,
            budget=budget,
        )

        self.assertEqual(first_result, second_result)
        self.assertEqual(remaining_edges, budget.remaining_edge_verifications)

        exhausted_budget = upload_server.SignatureVerificationBudget(
            remaining_chain_states=1
        )
        with self.assertRaisesRegex(
            upload_server.SignaturePolicyError,
            "certificate_chain_total_budget_exceeded",
        ):
            upload_server._build_trusted_certificate_chain(
                chain.leaf,
                [chain.intermediate],
                make_bundle(chain.root),
                TEST_TIME,
                budget=exhausted_budget,
            )

    def test_ca_eku_and_unhandled_critical_constraints_are_enforced(self):
        eku_restricted_chain = make_test_chain(
            intermediate_extended_key_usage=(ExtendedKeyUsageOID.CLIENT_AUTH,)
        )
        self.assertIsNone(
            upload_server._build_trusted_certificate_chain(
                eku_restricted_chain.leaf,
                [eku_restricted_chain.intermediate],
                make_bundle(eku_restricted_chain.root),
                TEST_TIME,
                required_extended_key_usage=ExtendedKeyUsageOID.CODE_SIGNING,
            )
        )

        constrained_chain = make_test_chain(
            intermediate_extra_extensions=(
                (
                    x509.NameConstraints(
                        permitted_subtrees=[x509.DNSName("example.test")],
                        excluded_subtrees=None,
                    ),
                    True,
                ),
            )
        )
        self.assertIsNone(
            upload_server._build_trusted_certificate_chain(
                constrained_chain.leaf,
                [constrained_chain.intermediate],
                make_bundle(constrained_chain.root),
                TEST_TIME,
            )
        )

    def test_self_issued_ca_does_not_consume_path_length(self):
        root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        shared_name = make_name("Rollover Root")
        root = make_certificate(
            subject=shared_name,
            issuer=shared_name,
            public_key=root_key.public_key(),
            issuer_key=root_key,
            is_ca=True,
            path_length=0,
        )
        rollover_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rollover = make_certificate(
            subject=shared_name,
            issuer=shared_name,
            public_key=rollover_key.public_key(),
            issuer_key=root_key,
            is_ca=True,
        )
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf = make_certificate(
            subject=make_name(upload_server.EXPECTED_SIGNER_CN),
            issuer=shared_name,
            public_key=leaf_key.public_key(),
            issuer_key=rollover_key,
            is_ca=False,
            extended_key_usage=(ExtendedKeyUsageOID.CODE_SIGNING,),
        )

        result = upload_server._build_trusted_certificate_chain(
            leaf,
            [rollover],
            make_bundle(root),
            TEST_TIME,
        )

        self.assertEqual([leaf, rollover, root], list(result))

    def test_distinguished_name_matching_normalizes_case_and_spaces(self):
        root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        root_subject = make_name("Normalized Root")
        root = make_certificate(
            subject=root_subject,
            issuer=root_subject,
            public_key=root_key.public_key(),
            issuer_key=root_key,
            is_ca=True,
        )
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf = make_certificate(
            subject=make_name(upload_server.EXPECTED_SIGNER_CN),
            issuer=make_name("  normalized   root  "),
            public_key=leaf_key.public_key(),
            issuer_key=root_key,
            is_ca=False,
            extended_key_usage=(ExtendedKeyUsageOID.CODE_SIGNING,),
        )

        result = upload_server._build_trusted_certificate_chain(
            leaf,
            [],
            make_bundle(root),
            TEST_TIME,
        )

        self.assertEqual([leaf, root], list(result))


class TestTimestampVerification(unittest.TestCase):
    def test_valid_rfc3161_timestamp_is_cryptographically_verified(self):
        parent_signature = b"authenticode-signer-signature"
        fixture = build_rfc3161_timestamp_token(parent_signature)

        result = upload_server._verify_rfc3161_timestamp_token(
            fixture.token,
            parent_signature,
            make_bundle(fixture.root),
        )

        self.assertEqual(TEST_TIME, result)

    def test_timestamp_signing_certificate_attribute_is_required_and_bound(self):
        parent_signature = b"authenticode-signer-signature"
        invalid_cases = [
            {"include_signing_certificate": False},
            {"signing_certificate_hash": b"x" * 32},
        ]

        for fixture_kwargs in invalid_cases:
            with self.subTest(fixture_kwargs=fixture_kwargs):
                fixture = build_rfc3161_timestamp_token(
                    parent_signature,
                    **fixture_kwargs,
                )
                with self.assertRaisesRegex(
                    upload_server.SignaturePolicyError,
                    "timestamp_signing_certificate_attribute_invalid",
                ):
                    upload_server._verify_rfc3161_timestamp_token(
                        fixture.token,
                        parent_signature,
                        make_bundle(fixture.root),
                    )

    def test_timestamp_message_imprint_mismatch_is_rejected(self):
        parent_signature = b"authenticode-signer-signature"
        fixture = build_rfc3161_timestamp_token(
            parent_signature,
            message_imprint=b"x" * 32,
        )

        with self.assertRaisesRegex(
            upload_server.SignaturePolicyError,
            "timestamp_message_imprint_mismatch",
        ):
            upload_server._verify_rfc3161_timestamp_token(
                fixture.token,
                parent_signature,
                make_bundle(fixture.root),
            )

    def test_timestamp_signature_mismatch_is_rejected(self):
        parent_signature = b"authenticode-signer-signature"
        fixture = build_rfc3161_timestamp_token(parent_signature)
        signer_info = fixture.token["content"]["signer_infos"][0]
        signer_info["signature"] = b"\x00" * len(signer_info["signature"].native)

        with self.assertRaisesRegex(
            upload_server.SignaturePolicyError,
            "cms_signature_invalid",
        ):
            upload_server._verify_rfc3161_timestamp_token(
                fixture.token,
                parent_signature,
                make_bundle(fixture.root),
            )

    def test_timestamp_certificate_must_chain_to_repository_bundle(self):
        parent_signature = b"authenticode-signer-signature"
        fixture = build_rfc3161_timestamp_token(parent_signature)
        unrelated_chain = make_test_chain()

        with self.assertRaisesRegex(
            upload_server.SignaturePolicyError,
            "timestamp_certificate_not_trusted",
        ):
            upload_server._verify_rfc3161_timestamp_token(
                fixture.token,
                parent_signature,
                make_bundle(unrelated_chain.root),
            )

    def test_timestamp_certificate_requires_timestamping_eku(self):
        parent_signature = b"authenticode-signer-signature"
        fixture = build_rfc3161_timestamp_token(
            parent_signature,
            timestamp_eku=False,
        )

        with self.assertRaisesRegex(
            upload_server.SignaturePolicyError,
            "timestamp_certificate_missing_eku",
        ):
            upload_server._verify_rfc3161_timestamp_token(
                fixture.token,
                parent_signature,
                make_bundle(fixture.root),
            )

    def test_timestamp_certificate_profile_is_strict(self):
        parent_signature = b"authenticode-signer-signature"
        invalid_cases = [
            (
                {"timestamp_is_ca": True},
                "timestamp_certificate_is_ca",
            ),
            (
                {
                    "timestamp_eku_oids": [
                        ExtendedKeyUsageOID.TIME_STAMPING,
                        ExtendedKeyUsageOID.CODE_SIGNING,
                    ]
                },
                "timestamp_certificate_wrong_eku",
            ),
            (
                {"timestamp_eku_critical": False},
                "timestamp_certificate_eku_not_critical",
            ),
            (
                {"timestamp_key_usage": non_signing_key_usage()},
                "timestamp_certificate_wrong_key_usage",
            ),
        ]

        for fixture_kwargs, expected_error in invalid_cases:
            with self.subTest(expected_error=expected_error):
                fixture = build_rfc3161_timestamp_token(
                    parent_signature,
                    **fixture_kwargs,
                )
                with self.assertRaisesRegex(
                    upload_server.SignaturePolicyError,
                    expected_error,
                ):
                    upload_server._verify_rfc3161_timestamp_token(
                        fixture.token,
                        parent_signature,
                        make_bundle(fixture.root),
                    )

    def test_standard_pkcs9_countersignature_omits_content_type(self):
        parent_signature = b"authenticode-signer-signature"
        fixture = build_pkcs9_countersignature(parent_signature)

        result = upload_server._verify_pkcs9_countersignature(
            fixture.signer_info,
            parent_signature,
            fixture.certificate_pairs,
            make_bundle(fixture.root),
        )

        self.assertEqual(TEST_TIME, result)

    def test_pkcs9_countersignature_rejects_content_type_and_duplicates(self):
        parent_signature = b"authenticode-signer-signature"
        invalid_cases = [
            (
                {"include_content_type": True},
                "countersignature_content_type_attribute_invalid",
            ),
            (
                {"duplicate_message_digest": True},
                "countersignature_message_digest_attribute_invalid",
            ),
        ]

        for fixture_kwargs, expected_error in invalid_cases:
            with self.subTest(expected_error=expected_error):
                fixture = build_pkcs9_countersignature(
                    parent_signature,
                    **fixture_kwargs,
                )
                with self.assertRaisesRegex(
                    upload_server.SignaturePolicyError,
                    expected_error,
                ):
                    upload_server._verify_pkcs9_countersignature(
                        fixture.signer_info,
                        parent_signature,
                        fixture.certificate_pairs,
                        make_bundle(fixture.root),
                    )


class TestAuthenticodePolicy(unittest.TestCase):
    def make_signature(self, chain, *, check_result=None, certificates=None):
        if check_result is None:
            check_result = upload_server.lief.PE.Signature.VERIFICATION_FLAGS.OK
        signer = SimpleNamespace(cert=FakeLiefCertificate(chain.leaf))
        if certificates is None:
            certificates = [chain.intermediate, chain.leaf]
        return SimpleNamespace(
            check=Mock(return_value=check_result),
            signers=[signer],
            certificates=[
                FakeLiefCertificate(certificate) for certificate in certificates
            ],
        )

    def test_exact_signer_identity_and_trusted_chain_are_accepted(self):
        chain = make_test_chain()
        signature = self.make_signature(chain)
        binary = Mock()
        binary.verify_signature.return_value = (
            upload_server.lief.PE.Signature.VERIFICATION_FLAGS.OK
        )

        with patch.object(
            upload_server,
            "_verify_signature_timestamps",
            return_value=(TEST_TIME,),
        ):
            result = upload_server._verify_authenticode_signature(
                binary,
                signature,
                make_bundle(chain.root),
            )

        self.assertTrue(result)

    def test_code_signer_certificate_profile_is_enforced(self):
        invalid_cases = [
            (
                {"leaf_include_basic_constraints": False},
                "signer_certificate_missing_basic_constraints",
            ),
            (
                {"leaf_is_ca": True},
                "signer_certificate_is_ca",
            ),
            (
                {"leaf_extended_key_usage": None},
                "signer_certificate_missing_eku",
            ),
            (
                {"leaf_extended_key_usage": (ExtendedKeyUsageOID.CLIENT_AUTH,)},
                "signer_certificate_wrong_eku",
            ),
            (
                {"leaf_key_usage": non_signing_key_usage()},
                "signer_certificate_wrong_key_usage",
            ),
        ]

        for chain_kwargs, expected_error in invalid_cases:
            with self.subTest(expected_error=expected_error):
                chain = make_test_chain(**chain_kwargs)
                signature = self.make_signature(chain)
                binary = Mock()
                binary.verify_signature.return_value = (
                    upload_server.lief.PE.Signature.VERIFICATION_FLAGS.OK
                )
                with self.assertRaisesRegex(
                    upload_server.SignaturePolicyError,
                    expected_error,
                ):
                    upload_server._verify_authenticode_signature(
                        binary,
                        signature,
                        make_bundle(chain.root),
                    )

    def test_certificate_order_does_not_change_signer_selection(self):
        chain = make_test_chain()
        signature = self.make_signature(
            chain,
            certificates=[chain.leaf, chain.intermediate],
        )
        binary = Mock()
        binary.verify_signature.return_value = (
            upload_server.lief.PE.Signature.VERIFICATION_FLAGS.OK
        )

        with patch.object(
            upload_server,
            "_verify_signature_timestamps",
            return_value=(TEST_TIME,),
        ):
            self.assertTrue(
                upload_server._verify_authenticode_signature(
                    binary,
                    signature,
                    make_bundle(chain.root),
                )
            )

    def test_signer_and_issuer_common_names_are_exact_and_unique(self):
        invalid_cases = [
            (("microsoft windows",), upload_server.EXPECTED_ISSUER_CN),
            (("Microsoft Windows ",), upload_server.EXPECTED_ISSUER_CN),
            (("Microsoft Windows", "Duplicate"), upload_server.EXPECTED_ISSUER_CN),
            (("Different Signer",), upload_server.EXPECTED_ISSUER_CN),
            ((upload_server.EXPECTED_SIGNER_CN,), "Different Issuer"),
        ]

        for signer_common_names, issuer_common_name in invalid_cases:
            with self.subTest(
                signer_common_names=signer_common_names,
                issuer_common_name=issuer_common_name,
            ):
                chain = make_test_chain(
                    signer_common_names=signer_common_names,
                    issuer_common_name=issuer_common_name,
                )
                signature = self.make_signature(chain)
                binary = Mock()
                binary.verify_signature.return_value = (
                    upload_server.lief.PE.Signature.VERIFICATION_FLAGS.OK
                )
                with (
                    patch.object(
                        upload_server,
                        "_verify_signature_timestamps",
                        return_value=(TEST_TIME,),
                    ),
                    self.assertRaises(upload_server.SignaturePolicyError),
                ):
                    upload_server._verify_authenticode_signature(
                        binary,
                        signature,
                        make_bundle(chain.root),
                    )

    def test_unknown_lief_flag_fails_closed(self):
        chain = make_test_chain()
        signature = self.make_signature(chain, check_result=object())

        with self.assertRaisesRegex(
            upload_server.SignaturePolicyError,
            "lief_signature_check_failed",
        ):
            upload_server._verify_authenticode_signature(
                Mock(),
                signature,
                make_bundle(chain.root),
            )

    def test_authentihash_flags_and_exceptions_fail_closed(self):
        chain = make_test_chain()
        signature = self.make_signature(chain)
        trusted_bundle = make_bundle(chain.root)
        flags = upload_server.lief.PE.Signature.VERIFICATION_FLAGS
        invalid_results = [
            flags.BAD_DIGEST,
            flags.BAD_SIGNATURE,
            int(flags.OK) | (1 << 30),
            False,
        ]

        for invalid_result in invalid_results:
            with self.subTest(invalid_result=invalid_result):
                binary = Mock()
                binary.verify_signature.return_value = invalid_result
                with (
                    patch.object(
                        upload_server,
                        "_WINDOWS_CODE_SIGNING_CA_BUNDLE",
                        trusted_bundle,
                    ),
                    patch.object(
                        upload_server.lief.PE,
                        "parse",
                        return_value=binary,
                    ),
                    patch.object(
                        upload_server,
                        "_iter_authenticode_signatures",
                        return_value=[signature],
                    ),
                    patch.object(
                        upload_server,
                        "_preflight_pe_certificate_table",
                        return_value=1,
                    ),
                    patch("sys.stderr", new_callable=StringIO),
                ):
                    self.assertFalse(upload_server.verify_signature(b"fake PE"))

        binary = Mock()
        binary.verify_signature.side_effect = RuntimeError("authentihash failed")
        with (
            patch.object(
                upload_server,
                "_WINDOWS_CODE_SIGNING_CA_BUNDLE",
                trusted_bundle,
            ),
            patch.object(upload_server.lief.PE, "parse", return_value=binary),
            patch.object(
                upload_server,
                "_iter_authenticode_signatures",
                return_value=[signature],
            ),
            patch.object(
                upload_server,
                "_preflight_pe_certificate_table",
                return_value=1,
            ),
            patch("sys.stderr", new_callable=StringIO),
        ):
            self.assertFalse(upload_server.verify_signature(b"fake PE"))

    def test_signer_certificate_must_be_present_exactly_once(self):
        chain = make_test_chain()
        signature = self.make_signature(
            chain,
            certificates=[chain.intermediate],
        )
        binary = Mock()
        binary.verify_signature.return_value = (
            upload_server.lief.PE.Signature.VERIFICATION_FLAGS.OK
        )

        with self.assertRaisesRegex(
            upload_server.SignaturePolicyError,
            "authenticode_signer_certificate_not_unique",
        ):
            upload_server._verify_authenticode_signature(
                binary,
                signature,
                make_bundle(chain.root),
            )

    def test_multi_signature_accepts_only_a_fully_qualified_signature(self):
        trusted_bundle = make_bundle(make_test_chain().root)
        fake_binary = object()
        signatures = [object(), object()]

        with (
            patch.object(
                upload_server,
                "_WINDOWS_CODE_SIGNING_CA_BUNDLE",
                trusted_bundle,
            ),
            patch.object(upload_server.lief.PE, "parse", return_value=fake_binary),
            patch.object(
                upload_server,
                "_iter_authenticode_signatures",
                return_value=signatures,
            ),
            patch.object(
                upload_server,
                "_verify_authenticode_signature",
                side_effect=[
                    upload_server.SignaturePolicyError("invalid_first_signature"),
                    True,
                ],
            ),
            patch.object(
                upload_server,
                "_preflight_pe_certificate_table",
                return_value=1,
            ),
            patch("sys.stderr", new_callable=StringIO),
        ):
            self.assertTrue(upload_server.verify_signature(b"fake PE"))

    def test_parse_and_verification_exceptions_fail_closed(self):
        trusted_bundle = make_bundle(make_test_chain().root)
        with (
            patch.object(
                upload_server,
                "_WINDOWS_CODE_SIGNING_CA_BUNDLE",
                trusted_bundle,
            ),
            patch.object(
                upload_server.lief.PE,
                "parse",
                side_effect=RuntimeError("parse failed"),
            ),
            patch.object(
                upload_server,
                "_preflight_pe_certificate_table",
                return_value=1,
            ),
            patch("sys.stderr", new_callable=StringIO),
        ):
            self.assertFalse(upload_server.verify_signature(b"broken PE"))

        with (
            patch.object(
                upload_server,
                "_WINDOWS_CODE_SIGNING_CA_BUNDLE",
                trusted_bundle,
            ),
            patch.object(upload_server.lief.PE, "parse", return_value=object()),
            patch.object(
                upload_server,
                "_iter_authenticode_signatures",
                return_value=[object()],
            ),
            patch.object(
                upload_server,
                "_verify_authenticode_signature",
                side_effect=RuntimeError("verification failed"),
            ),
            patch.object(
                upload_server,
                "_preflight_pe_certificate_table",
                return_value=1,
            ),
            patch("sys.stderr", new_callable=StringIO),
        ):
            self.assertFalse(upload_server.verify_signature(b"broken signature"))

    def test_verify_signature_requires_startup_ca_preflight(self):
        with (
            patch.object(
                upload_server,
                "_WINDOWS_CODE_SIGNING_CA_BUNDLE",
                None,
            ),
            patch.object(upload_server.lief.PE, "parse") as parse,
            patch("sys.stderr", new_callable=StringIO),
        ):
            self.assertFalse(upload_server.verify_signature(b"fake PE"))

        parse.assert_not_called()


class TestSignatureResourceLimits(unittest.TestCase):
    @staticmethod
    def make_enumerated_signature(raw_der, attributes=()):
        return SimpleNamespace(
            raw_der=raw_der,
            signers=[
                SimpleNamespace(
                    unauthenticated_attributes=list(attributes),
                )
            ],
        )

    @staticmethod
    def make_pe_with_certificate_payloads(*payloads):
        pe_offset = 0x80
        optional_header_offset = pe_offset + 24
        certificate_table_offset = 0x200
        headers = bytearray(certificate_table_offset)
        headers[:2] = b"MZ"
        headers[0x3C:0x40] = pe_offset.to_bytes(4, "little")
        headers[pe_offset : pe_offset + 4] = b"PE\0\0"
        headers[pe_offset + 20 : pe_offset + 22] = (0xF0).to_bytes(2, "little")
        headers[optional_header_offset : optional_header_offset + 2] = (0x20B).to_bytes(
            2, "little"
        )
        headers[optional_header_offset + 108 : optional_header_offset + 112] = (
            16
        ).to_bytes(4, "little")

        certificate_table = bytearray()
        for payload in payloads:
            certificate_length = 8 + len(payload)
            certificate_table.extend(certificate_length.to_bytes(4, "little"))
            certificate_table.extend((0x0200).to_bytes(2, "little"))
            certificate_table.extend((0x0002).to_bytes(2, "little"))
            certificate_table.extend(payload)
            certificate_table.extend(b"\0" * ((-certificate_length) % 8))

        security_directory_offset = optional_header_offset + 112 + (4 * 8)
        headers[security_directory_offset : security_directory_offset + 4] = (
            certificate_table_offset.to_bytes(4, "little")
        )
        headers[security_directory_offset + 4 : security_directory_offset + 8] = len(
            certificate_table
        ).to_bytes(4, "little")
        return bytes(headers + certificate_table)

    def test_signature_count_and_der_size_limits(self):
        first = self.make_enumerated_signature(b"first")
        second = self.make_enumerated_signature(b"second")
        with (
            patch.object(upload_server, "MAX_AUTHENTICODE_SIGNATURES", 1),
            self.assertRaisesRegex(
                upload_server.SignaturePolicyError,
                "signature_count_limit_exceeded",
            ),
        ):
            list(
                upload_server._iter_authenticode_signatures(
                    SimpleNamespace(signatures=[first, second])
                )
            )

        with (
            patch.object(upload_server, "MAX_SIGNATURE_DER_SIZE", 4),
            self.assertRaisesRegex(
                upload_server.SignaturePolicyError,
                "signature_der_size_limit_exceeded",
            ),
        ):
            list(
                upload_server._iter_authenticode_signatures(
                    SimpleNamespace(signatures=[first])
                )
            )

        with (
            patch.object(upload_server, "MAX_SIGNATURE_DER_SIZE", 10),
            patch.object(upload_server, "MAX_TOTAL_SIGNATURE_DER_SIZE", 9),
            self.assertRaisesRegex(
                upload_server.SignaturePolicyError,
                "signature_der_total_size_limit_exceeded",
            ),
        ):
            list(
                upload_server._iter_authenticode_signatures(
                    SimpleNamespace(signatures=[first, second])
                )
            )

    def test_raw_pe_certificate_table_limits_precede_lief(self):
        file_data = self.make_pe_with_certificate_payloads(b"one", b"two")
        self.assertEqual(2, upload_server._preflight_pe_certificate_table(file_data))

        with (
            patch.object(upload_server, "MAX_AUTHENTICODE_SIGNATURES", 1),
            self.assertRaisesRegex(
                upload_server.SignaturePolicyError,
                "signature_count_limit_exceeded",
            ),
        ):
            upload_server._preflight_pe_certificate_table(file_data)

        with (
            patch.object(
                upload_server,
                "MAX_PE_CERTIFICATE_TABLE_SIZE",
                1,
            ),
            self.assertRaisesRegex(
                upload_server.SignaturePolicyError,
                "pe_certificate_table_size_limit_exceeded",
            ),
        ):
            upload_server._preflight_pe_certificate_table(file_data)

        malformed_data = bytearray(file_data)
        malformed_data[0x200:0x204] = (0).to_bytes(4, "little")
        with self.assertRaisesRegex(
            upload_server.SignaturePolicyError,
            "win_certificate_length_invalid",
        ):
            upload_server._preflight_pe_certificate_table(bytes(malformed_data))

    def test_nested_signature_depth_and_count_limits(self):
        grandchild = self.make_enumerated_signature(b"grandchild")
        child_attribute = SimpleNamespace(sig=grandchild)
        child = self.make_enumerated_signature(b"child", [child_attribute])
        root_attribute = SimpleNamespace(sig=child)
        root = self.make_enumerated_signature(b"root", [root_attribute])

        with (
            patch.object(upload_server, "MAX_NESTED_SIGNATURE_DEPTH", 1),
            patch.object(
                upload_server,
                "_nested_authenticode_signature",
                side_effect=lambda attribute: attribute.sig,
            ),
            self.assertRaisesRegex(
                upload_server.SignaturePolicyError,
                "nested_signature_depth_limit_exceeded",
            ),
        ):
            list(
                upload_server._iter_authenticode_signatures(
                    SimpleNamespace(signatures=[root])
                )
            )

        first_nested = self.make_enumerated_signature(b"nested-one")
        second_nested = self.make_enumerated_signature(b"nested-two")
        root = self.make_enumerated_signature(
            b"root",
            [
                SimpleNamespace(sig=first_nested),
                SimpleNamespace(sig=second_nested),
            ],
        )
        with (
            patch.object(upload_server, "MAX_NESTED_SIGNATURES", 1),
            patch.object(
                upload_server,
                "_nested_authenticode_signature",
                side_effect=lambda attribute: attribute.sig,
            ),
            self.assertRaisesRegex(
                upload_server.SignaturePolicyError,
                "nested_signature_count_limit_exceeded",
            ),
        ):
            list(
                upload_server._iter_authenticode_signatures(
                    SimpleNamespace(signatures=[root])
                )
            )

    def test_certificate_and_timestamp_limits(self):
        chain = make_test_chain()
        signature = SimpleNamespace(
            check=Mock(
                return_value=upload_server.lief.PE.Signature.VERIFICATION_FLAGS.OK
            ),
            signers=[SimpleNamespace(cert=FakeLiefCertificate(chain.leaf))],
            certificates=[
                FakeLiefCertificate(chain.intermediate),
                FakeLiefCertificate(chain.leaf),
            ],
        )
        binary = Mock()
        binary.verify_signature.return_value = (
            upload_server.lief.PE.Signature.VERIFICATION_FLAGS.OK
        )
        with (
            patch.object(
                upload_server,
                "MAX_EMBEDDED_CERTIFICATES_PER_SIGNATURE",
                1,
            ),
            self.assertRaisesRegex(
                upload_server.SignaturePolicyError,
                "embedded_certificate_limit_exceeded",
            ),
        ):
            upload_server._verify_authenticode_signature(
                binary,
                signature,
                make_bundle(chain.root),
            )

        timestamp_attribute = {
            "type": SimpleNamespace(dotted=upload_server.MICROSOFT_TIMESTAMP_TOKEN_OID),
            "values": [
                SimpleNamespace(dump=lambda: b"timestamp-one"),
                SimpleNamespace(dump=lambda: b"timestamp-two"),
            ],
        }
        with (
            patch.object(upload_server, "MAX_TIMESTAMP_VALUES_PER_SIGNATURE", 1),
            self.assertRaisesRegex(
                upload_server.SignaturePolicyError,
                "timestamp_value_limit_exceeded",
            ),
        ):
            upload_server._collect_signature_timestamp_entries([timestamp_attribute])

        duplicate_timestamp = SimpleNamespace(dump=lambda: b"same-timestamp")
        timestamp_attribute["values"] = [
            duplicate_timestamp,
            duplicate_timestamp,
        ]
        self.assertEqual(
            1,
            len(
                upload_server._collect_signature_timestamp_entries(
                    [timestamp_attribute]
                )
            ),
        )


class TestPeMetadataValidation(unittest.TestCase):
    def test_parser_exception_log_is_bounded(self):
        file_data = b"not a PE"
        stderr = StringIO()
        with (
            patch.object(
                upload_server.pefile,
                "PE",
                side_effect=RuntimeError("secret parser detail\nforged log line"),
            ),
            patch("sys.stderr", stderr),
        ):
            self.assertIsNone(upload_server.verify_pe_file(file_data))

        log_output = stderr.getvalue()
        self.assertIn(hashlib.sha256(file_data).hexdigest(), log_output)
        self.assertIn("pe_parse_exception_RuntimeError", log_output)
        self.assertNotIn("secret parser detail", log_output)
        self.assertNotIn("forged log line", log_output)


class TestRealAuthenticodeSmoke(unittest.TestCase):
    def test_opt_in_microsoft_pe_and_tamper_rejection(self):
        pe_path_value = os.environ.get("KPHTOOLS_AUTHENTICODE_TEST_PE")
        if not pe_path_value:
            self.skipTest("KPHTOOLS_AUTHENTICODE_TEST_PE is not set")
        pe_path = Path(pe_path_value)
        file_data = pe_path.read_bytes()
        if len(file_data) <= 4096:
            self.fail("The opt-in PE is too small for the tamper smoke test")

        previous_bundle = upload_server._WINDOWS_CODE_SIGNING_CA_BUNDLE
        try:
            upload_server.preflight_windows_code_signing_ca_bundle()
            self.assertTrue(upload_server.verify_signature(file_data))

            tampered_data = bytearray(file_data)
            tampered_data[4096] ^= 1
            with patch("sys.stderr", new_callable=StringIO):
                self.assertFalse(upload_server.verify_signature(bytes(tampered_data)))

            parsed_pe = upload_server.pefile.PE(data=file_data, fast_load=True)
            security_directory = parsed_pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                upload_server.pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
            ]
            certificate_tamper = bytearray(file_data)
            certificate_tamper[security_directory.VirtualAddress + 20] ^= 1
            with patch("sys.stderr", new_callable=StringIO):
                self.assertFalse(
                    upload_server.verify_signature(bytes(certificate_tamper))
                )

            lief_binary = upload_server.lief.PE.parse(file_data)
            signer_der = bytes(lief_binary.signatures[0].signers[0].cert.raw)
            signer_offset = file_data.find(signer_der)
            identity_offset = signer_der.rfind(b"Microsoft Windows")
            self.assertGreaterEqual(signer_offset, 0)
            self.assertGreaterEqual(identity_offset, 0)
            identity_tamper = bytearray(file_data)
            identity_tamper[signer_offset + identity_offset] = ord("N")
            with patch("sys.stderr", new_callable=StringIO):
                self.assertFalse(upload_server.verify_signature(bytes(identity_tamper)))

            storage = RecordingStorage()
            handler = object.__new__(upload_server.UploadHandler)
            handler.storage = storage
            handler.path = "/upload"
            handler.headers = {
                "Content-Length": str(len(file_data)),
                "Content-Type": "application/octet-stream",
            }
            handler.rfile = BytesIO(file_data)
            handler.send_json_response = Mock()
            handler.do_POST()
            self.assertEqual(1, len(storage.saved))

            rejected_storage = RecordingStorage()
            rejected_handler = object.__new__(upload_server.UploadHandler)
            rejected_handler.storage = rejected_storage
            rejected_handler.path = "/upload"
            rejected_handler.headers = {
                "Content-Length": str(len(tampered_data)),
                "Content-Type": "application/octet-stream",
            }
            rejected_handler.rfile = BytesIO(bytes(tampered_data))
            rejected_handler.send_json_response = Mock()
            with patch("sys.stderr", new_callable=StringIO):
                rejected_handler.do_POST()
            self.assertEqual([], rejected_storage.saved)
            rejected_handler.send_json_response.assert_called_once_with(
                400,
                "Digital signature verification failed or does not match requirements",
            )
        finally:
            upload_server._WINDOWS_CODE_SIGNING_CA_BUNDLE = previous_bundle


class TestStorageConfiguration(unittest.TestCase):
    def test_parse_args_defaults_to_symbols(self):
        with patch.dict(os.environ, {}, clear=True):
            args = upload_server.parse_args([])

        self.assertEqual("symbols", args.symboldir)

    def test_parse_args_prefers_environment_symboldir(self):
        with patch.dict(os.environ, {"KPHTOOLS_SYMBOLDIR": "env-symbols"}, clear=True):
            args = upload_server.parse_args(["-symboldir", "cli-symbols"])

        self.assertEqual("env-symbols", args.symboldir)

    def test_storage_mode_defaults_to_disk_and_is_case_insensitive(self):
        self.assertEqual("disk", upload_server.get_storage_mode({}))
        self.assertEqual(
            "oss",
            upload_server.get_storage_mode({"KPHTOOLS_SERVER_STORAGE": " OSS "}),
        )

    def test_storage_mode_rejects_unknown_value(self):
        with self.assertRaisesRegex(ValueError, "KPHTOOLS_SERVER_STORAGE"):
            upload_server.get_storage_mode({"KPHTOOLS_SERVER_STORAGE": "mirror"})

    def test_disk_storage_requires_symbol_directory(self):
        with self.assertRaisesRegex(ValueError, "symboldir"):
            upload_server.create_storage_backend("disk", symboldir=None)

    def test_oss_storage_requires_all_configuration(self):
        with self.assertRaisesRegex(ValueError, "KPHTOOLS_SERVER_OSS_REGION"):
            upload_server.create_storage_backend(
                "oss",
                environ={},
                oss_module=FakeOssModule,
            )

    def test_oss_storage_requires_standard_sdk_credentials(self):
        environ = {
            "KPHTOOLS_SERVER_OSS_REGION": "cn-hangzhou",
            "KPHTOOLS_SERVER_OSS_BUCKET": "kernel-symbols",
        }

        with self.assertRaisesRegex(ValueError, "OSS_ACCESS_KEY_ID"):
            upload_server.create_storage_backend(
                "oss",
                environ=environ,
                oss_module=FakeOssModule,
            )

    def test_oss_storage_uses_environment_configuration(self):
        environ = {
            "KPHTOOLS_SERVER_OSS_REGION": "cn-hangzhou",
            "KPHTOOLS_SERVER_OSS_BUCKET": "kernel-symbols",
            "KPHTOOLS_SERVER_OSS_ENDPOINT": "oss-cn-hangzhou-internal.aliyuncs.com",
            "KPHTOOLS_SERVER_OSS_PREFIX": "/symbols/uploads/",
            "OSS_ACCESS_KEY_ID": "access-key-id",
            "OSS_ACCESS_KEY_SECRET": "access-key-secret",
        }

        storage = upload_server.create_storage_backend(
            "oss",
            environ=environ,
            oss_module=FakeOssModule,
        )

        self.assertIsInstance(storage, upload_server.OssStorage)
        self.assertEqual("kernel-symbols", storage.bucket)
        self.assertEqual("symbols/uploads", storage.prefix)
        self.assertEqual("cn-hangzhou", storage.client.config.region)
        self.assertEqual(
            "oss-cn-hangzhou-internal.aliyuncs.com",
            storage.client.config.endpoint,
        )
        self.assertIsInstance(
            storage.client.config.credentials_provider,
            FakeCredentialsProvider,
        )

    def test_oss_storage_does_not_create_local_symbol_directory(self):
        environ = {
            "KPHTOOLS_SERVER_OSS_REGION": "cn-hangzhou",
            "KPHTOOLS_SERVER_OSS_BUCKET": "kernel-symbols",
            "OSS_ACCESS_KEY_ID": "access-key-id",
            "OSS_ACCESS_KEY_SECRET": "access-key-secret",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            symbol_dir = os.path.join(temp_dir, "symbols")
            upload_server.create_storage_backend(
                "oss",
                symboldir=symbol_dir,
                environ=environ,
                oss_module=FakeOssModule,
            )

            self.assertFalse(os.path.exists(symbol_dir))

    def test_real_oss_sdk_can_initialize_without_network_access(self):
        environ = {
            "KPHTOOLS_SERVER_OSS_REGION": "cn-hangzhou",
            "KPHTOOLS_SERVER_OSS_BUCKET": "kernel-symbols",
            "OSS_ACCESS_KEY_ID": "access-key-id",
            "OSS_ACCESS_KEY_SECRET": "access-key-secret",
        }

        with patch.dict(os.environ, environ, clear=True):
            storage = upload_server.create_storage_backend("oss")

        self.assertIsInstance(storage, upload_server.OssStorage)
        self.assertEqual("kernel-symbols", storage.bucket)


class TestDiskStorage(unittest.TestCase):
    def test_build_symbol_path_uses_forward_slashes(self):
        path = upload_server.build_symbol_path(
            "amd64",
            "ntoskrnl.exe",
            "10.0.26100.1",
            "a" * 64,
        )

        self.assertEqual(
            f"amd64/ntoskrnl.exe.10.0.26100.1/{'a' * 64}/ntoskrnl.exe",
            path,
        )

    def test_save_stat_and_duplicate_behavior(self):
        file_data = b"kernel-data"
        file_hash = hashlib.sha256(file_data).hexdigest()
        relative_path = upload_server.build_symbol_path(
            "amd64",
            "ntoskrnl.exe",
            "10.0.26100.1",
            file_hash,
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            storage = upload_server.DiskStorage(temp_dir)

            result = storage.save_file(relative_path, file_data, file_hash)
            exists, file_size = storage.stat_file(relative_path)
            duplicate = storage.save_file(relative_path, file_data, file_hash)
            conflict = storage.save_file(
                relative_path,
                b"different-data",
                hashlib.sha256(b"different-data").hexdigest(),
            )

        self.assertEqual((True, "File uploaded successfully", 200), result)
        self.assertTrue(exists)
        self.assertEqual(len(file_data), file_size)
        self.assertEqual(
            (True, "File already exists and is identical", 200),
            duplicate,
        )
        self.assertEqual(
            (False, "File already exists with different content", 409),
            conflict,
        )


class TestOssStorage(unittest.TestCase):
    def setUp(self):
        self.client = Mock()
        self.storage = upload_server.OssStorage(
            self.client,
            FakeOssModule,
            "kernel-symbols",
            "/symbols/",
        )
        self.relative_path = f"amd64/ntoskrnl.exe.10.0.26100.1/{'a' * 64}/ntoskrnl.exe"

    def test_stat_returns_content_length(self):
        self.client.head_object.return_value = SimpleNamespace(content_length=1234)

        result = self.storage.stat_file(self.relative_path)

        self.assertEqual((True, 1234), result)
        request = self.client.head_object.call_args.args[0]
        self.assertEqual("kernel-symbols", request.bucket)
        self.assertEqual(f"symbols/{self.relative_path}", request.key)

    def test_stat_treats_only_no_such_key_as_missing(self):
        self.client.head_object.side_effect = real_oss.exceptions.OperationError(
            name="head_object", error=FakeServiceError(404, "NoSuchKey")
        )

        self.assertEqual((False, None), self.storage.stat_file(self.relative_path))

    def test_stat_maps_other_errors_to_storage_error(self):
        self.client.head_object.side_effect = FakeServiceError(404, "NoSuchBucket")

        with (
            patch("sys.stderr", new_callable=StringIO),
            self.assertRaisesRegex(
                upload_server.StorageError,
                "OSS storage operation failed",
            ),
        ):
            self.storage.stat_file(self.relative_path)

    def test_stat_maps_network_errors_to_storage_error(self):
        self.client.head_object.side_effect = TimeoutError("network timeout")

        with (
            patch("sys.stderr", new_callable=StringIO),
            self.assertRaisesRegex(
                upload_server.StorageError,
                "OSS storage operation failed",
            ),
        ):
            self.storage.stat_file(self.relative_path)

    def test_uploads_bytes_without_overwriting(self):
        file_data = b"kernel-data"
        file_hash = hashlib.sha256(file_data).hexdigest()
        self.client.head_object.side_effect = FakeServiceError(404, "NoSuchKey")

        result = self.storage.save_file(self.relative_path, file_data, file_hash)

        self.assertEqual((True, "File uploaded successfully", 200), result)
        request = self.client.put_object.call_args.args[0]
        self.assertEqual("kernel-symbols", request.bucket)
        self.assertEqual(f"symbols/{self.relative_path}", request.key)
        self.assertEqual(file_data, request.body.read())
        self.assertEqual("application/octet-stream", request.content_type)
        self.assertTrue(request.forbid_overwrite)

    def test_existing_object_is_idempotent_success(self):
        self.client.head_object.return_value = SimpleNamespace(
            content_length=len(b"kernel-data")
        )

        result = self.storage.save_file(
            self.relative_path,
            b"kernel-data",
            "a" * 64,
        )

        self.assertEqual(
            (True, "File already exists and is identical", 200),
            result,
        )
        self.client.put_object.assert_not_called()

    def test_concurrent_conflict_is_idempotent_success(self):
        self.client.head_object.side_effect = real_oss.exceptions.OperationError(
            name="head_object", error=FakeServiceError(404, "NoSuchKey")
        )
        self.client.put_object.side_effect = real_oss.exceptions.OperationError(
            name="put_object", error=FakeServiceError(409, "FileAlreadyExists")
        )

        result = self.storage.save_file(
            self.relative_path,
            b"kernel-data",
            "a" * 64,
        )

        self.assertEqual(
            (True, "File already exists and is identical", 200),
            result,
        )

    def test_upload_maps_non_conflict_errors_to_storage_error(self):
        self.client.head_object.side_effect = FakeServiceError(404, "NoSuchKey")
        self.client.put_object.side_effect = FakeServiceError(403, "AccessDenied")

        with (
            patch("sys.stderr", new_callable=StringIO),
            self.assertRaisesRegex(
                upload_server.StorageError,
                "OSS storage operation failed",
            ),
        ):
            self.storage.save_file(
                self.relative_path,
                b"kernel-data",
                "a" * 64,
            )


class TestUploadHandlerStorageIntegration(unittest.TestCase):
    def test_exists_uses_injected_storage_and_preserves_response_path(self):
        storage = RecordingStorage(exists=True, file_size=1234)
        handler = object.__new__(upload_server.UploadHandler)
        handler.storage = storage
        handler.path = (
            "/exists?filename=ntoskrnl.exe&arch=amd64&fileversion=10.0.26100.1"
            f"&sha256={'a' * 64}"
        )
        handler.send_json_response = Mock()

        handler.do_GET()

        expected_path = f"amd64/ntoskrnl.exe.10.0.26100.1/{'a' * 64}/ntoskrnl.exe"
        self.assertEqual(expected_path, storage.stat_path)
        handler.send_json_response.assert_called_once_with(
            200,
            "File existence checked",
            {
                "filename": "ntoskrnl.exe",
                "arch": "amd64",
                "fileversion": "10.0.26100.1",
                "sha256": "a" * 64,
                "exists": True,
                "path": expected_path,
                "file_size": 1234,
            },
        )

    def test_exists_maps_storage_error_to_bad_gateway(self):
        storage = Mock()
        storage.stat_file.side_effect = upload_server.StorageError(
            "OSS storage operation failed"
        )
        handler = object.__new__(upload_server.UploadHandler)
        handler.storage = storage
        handler.path = (
            "/exists?filename=ntoskrnl.exe&arch=amd64&fileversion=10.0.26100.1"
            f"&sha256={'a' * 64}"
        )
        handler.send_json_response = Mock()

        handler.do_GET()

        handler.send_json_response.assert_called_once_with(
            502,
            "OSS storage operation failed",
        )

    def test_upload_uses_injected_storage(self):
        file_data = b"kernel-data"
        file_hash = hashlib.sha256(file_data).hexdigest()
        storage = RecordingStorage()
        handler = object.__new__(upload_server.UploadHandler)
        handler.storage = storage
        handler.path = "/upload"
        handler.headers = {
            "Content-Length": str(len(file_data)),
            "Content-Type": "application/octet-stream",
        }
        handler.rfile = BytesIO(file_data)
        handler.send_json_response = Mock()

        with (
            patch(
                "upload_server.verify_pe_file",
                return_value={
                    "file_name": "ntoskrnl.exe",
                    "file_version": "10.0.26100.1",
                    "arch": "amd64",
                },
            ),
            patch("upload_server.verify_signature", return_value=True),
        ):
            handler.do_POST()

        self.assertEqual(1, len(storage.saved))
        relative_path, saved_data, saved_hash = storage.saved[0]
        self.assertEqual(file_data, saved_data)
        self.assertEqual(file_hash, saved_hash)
        self.assertEqual(
            f"amd64/ntoskrnl.exe.10.0.26100.1/{file_hash}/ntoskrnl.exe",
            relative_path,
        )
        handler.send_json_response.assert_called_once_with(
            200,
            "File uploaded successfully",
            {
                "file_name": "ntoskrnl.exe",
                "file_version": "10.0.26100.1",
                "arch": "amd64",
                "sha256": file_hash,
            },
        )

    def test_upload_rejects_invalid_signature_before_storage(self):
        file_data = b"kernel-data"
        storage = RecordingStorage()
        handler = object.__new__(upload_server.UploadHandler)
        handler.storage = storage
        handler.path = "/upload"
        handler.headers = {
            "Content-Length": str(len(file_data)),
            "Content-Type": "application/octet-stream",
        }
        handler.rfile = BytesIO(file_data)
        handler.send_json_response = Mock()

        with (
            patch(
                "upload_server.verify_pe_file",
                return_value={
                    "file_name": "ntoskrnl.exe",
                    "file_version": "10.0.26100.1",
                    "arch": "amd64",
                },
            ),
            patch("upload_server.verify_signature", return_value=False),
        ):
            handler.do_POST()

        self.assertEqual([], storage.saved)
        handler.send_json_response.assert_called_once_with(
            400,
            "Digital signature verification failed or does not match requirements",
        )


if __name__ == "__main__":
    unittest.main()
