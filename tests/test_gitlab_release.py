"""GitLab release policy and orchestration fixtures, not hosted identity proof."""

import base64
import copy
import hashlib
import json
import runpy
import shutil
import subprocess
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier

from certweaver.registry import project_root

tools = runpy.run_path(str(project_root() / "scripts/gitlab-release.py"))
workflows = runpy.run_path(str(project_root() / "scripts/check-release-workflows.py"))
POLICY = tools["policy"]("https://gitlab.com/example/certweaver", "12345", "v0.1.0", "a" * 40)
INVOCATION = POLICY["project"] + "/-/jobs/123456"
SUBJECTS = [{"name": "dist/fixture.whl", "digest": {"sha256": "b" * 64}}]


def context():
    return {
        "CI": "true",
        "GITLAB_CI": "true",
        "CI_SERVER_URL": "https://gitlab.com",
        "CI_PIPELINE_SOURCE": "push",
        "CI_COMMIT_REF_PROTECTED": "true",
        "CI_CONFIG_PATH": ".gitlab-ci.yml",
        "CI_JOB_NAME": "sign-release",
        "CI_ENVIRONMENT_NAME": "release",
        "CI_PROJECT_URL": POLICY["project"],
        "CI_PROJECT_ID": "12345",
        "CI_PROJECT_PATH": "example/certweaver",
        "CI_COMMIT_TAG": "v0.1.0",
        "CI_COMMIT_SHA": "a" * 40,
        "CI_JOB_ID": "123456",
        "CI_PIPELINE_ID": "1234",
    }


def leaf(changed=None, *, missing=None):
    # Self-signed unit certificate used only to exercise extension comparisons.
    # Production Cosign verification never trusts this fixture certificate.
    values = {
        8: POLICY["issuer"],
        9: POLICY["identity"],
        10: POLICY["commit"],
        12: POLICY["project"],
        13: POLICY["commit"],
        14: "refs/tags/" + POLICY["tag"],
        15: POLICY["projectId"],
        18: POLICY["identity"],
        19: POLICY["commit"],
        20: "push",
        21: INVOCATION,
        23: "release",
    }
    if changed:
        values.update(changed)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic policy fixture")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=5))
        .not_valid_after(datetime.now(UTC) + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(POLICY["identity"])]),
            critical=False,
        )
    )
    for number, value in values.items():
        if number != missing:
            builder = builder.add_extension(
                x509.UnrecognizedExtension(
                    ObjectIdentifier("1.3.6.1.4.1.57264.1." + str(number)),
                    tools["utf8_extension"](value),
                ),
                critical=False,
            )
    return builder.sign(key, hashes.SHA256())


def bundle(certificate=None):
    certificate = certificate or leaf()
    return {
        "mediaType": tools["MEDIA_TYPE"],
        "messageSignature": {"signature": "fixture"},
        "verificationMaterial": {
            "certificate": {
                "rawBytes": base64.b64encode(
                    certificate.public_bytes(serialization.Encoding.DER)
                ).decode()
            },
            "tlogEntries": [{"synthetic": True}],
        },
    }


def test_policy_restricts_signing_context_and_assembles_exact_identity():
    selected, invocation = tools["ci_context"](context())
    assert selected == POLICY and invocation == INVOCATION
    tools["certificate_policy"](leaf(), POLICY, INVOCATION)
    tools["certificate_policy"](
        leaf({10: "sha1:" + "a" * 40, 13: "sha1:" + "a" * 40, 19: "sha1:" + "a" * 40}),
        POLICY,
        INVOCATION,
    )


@pytest.mark.parametrize(
    "name,value",
    [
        ("CI_SERVER_URL", "https://other.example"),
        ("CI_PIPELINE_SOURCE", "merge_request_event"),
        ("CI_COMMIT_REF_PROTECTED", "false"),
        ("CI_CONFIG_PATH", "other.yml"),
        ("CI_JOB_NAME", "package"),
        ("CI_ENVIRONMENT_NAME", "production"),
        ("CI_PROJECT_ID", "0"),
        ("CI_PROJECT_PATH", "other/project"),
        ("CI_PROJECT_URL", "https://gitlab.com@example.invalid/example/certweaver"),
        ("CI_COMMIT_SHA", "main"),
        ("CI_COMMIT_TAG", "v0.1.0;echo unsafe"),
        ("CI_JOB_ID", "-1"),
        ("CI_PIPELINE_ID", "not-a-pipeline"),
        ("CI_DEBUG_TRACE", "true"),
    ],
)
def test_unsafe_or_ambiguous_signing_context_is_rejected(name, value):
    environment = context()
    environment[name] = value
    with pytest.raises(ValueError):
        tools["ci_context"](environment)


@pytest.mark.parametrize("number", [8, 9, 10, 12, 13, 14, 15, 18, 19, 20, 21, 23])
def test_authenticated_certificate_fields_cannot_be_substituted_or_omitted(number):
    with pytest.raises(ValueError, match="policy mismatch"):
        tools["certificate_policy"](leaf({number: "untrusted-other-value"}), POLICY, INVOCATION)
    with pytest.raises(x509.ExtensionNotFound):
        tools["certificate_policy"](leaf(missing=number), POLICY, INVOCATION)


@pytest.mark.parametrize("change", ["legacy", "key-only", "chain", "no-log", "no-signature"])
def test_keyless_mode_refuses_legacy_key_or_missing_transparency_material(change):
    value = bundle()
    if change == "legacy":
        value["mediaType"] = "application/vnd.dev.sigstore.bundle+json;version=0.2"
    elif change == "key-only":
        value["verificationMaterial"] = {"publicKey": {"hint": "not-an-identity"}}
    elif change == "chain":
        value["verificationMaterial"]["x509CertificateChain"] = {"certificates": []}
    elif change == "no-log":
        value["verificationMaterial"]["tlogEntries"] = []
    else:
        del value["messageSignature"]
    with pytest.raises(ValueError):
        tools["certificate"](value)


@pytest.mark.parametrize("change", [None, "source", "workflow", "subject", "extra", "bundle-race"])
def test_intake_checks_the_signed_manifest_and_same_certificate_bytes(
    tmp_path, monkeypatch, change
):
    evidence = tmp_path / "release-evidence"
    evidence.mkdir()
    value = tools["statement"](POLICY, INVOCATION, copy.deepcopy(SUBJECTS))
    if change == "source":
        value["predicate"]["buildDefinition"]["externalParameters"]["source"]["digest"] = {
            "sha1": "c" * 40
        }
    elif change == "workflow":
        value["predicate"]["runDetails"]["builder"]["id"] += ".wrong"
    elif change == "subject":
        value["subject"] += copy.deepcopy(value["subject"])
    elif change == "extra":
        value["unexpected"] = "unreviewed input"
    (evidence / tools["PROVENANCE"]).write_text(json.dumps(value), encoding="utf-8")
    (evidence / tools["BUNDLE"]).write_text(json.dumps(bundle()), encoding="utf-8")
    namespace = tools["verify_release"].__globals__

    def verified(*args, **kwargs):
        if change == "bundle-race":
            (evidence / tools["BUNDLE"]).write_text(
                json.dumps(bundle(leaf({13: "c" * 40}))), encoding="utf-8"
            )
        return {"scope": "Signature verifier mocked in this policy unit fixture only"}

    monkeypatch.setitem(namespace, "verify_blob", verified)
    monkeypatch.setitem(namespace, "checked_subjects", lambda *args, **kwargs: SUBJECTS)
    if change:
        with pytest.raises(ValueError):
            tools["verify_release"](tmp_path, tmp_path, tmp_path / "unused", POLICY)
    else:
        result = tools["verify_release"](tmp_path, tmp_path, tmp_path / "unused", POLICY)
        assert result["status"] == "GITLAB_RELEASE_INTAKE_VERIFIED_NOT_PRODUCTION_APPROVAL"


def test_crypto_wrapper_uses_exact_flags_and_isolated_configuration(tmp_path, monkeypatch):
    binary = tmp_path / "never-executed"
    binary.write_bytes(b"synthetic crypto wrapper executable")
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"synthetic blob")
    signature = tmp_path / "signature.json"
    signature.write_text(json.dumps(bundle()), encoding="utf-8")
    calls = []
    monkeypatch.setitem(
        tools["verify_blob"].__globals__,
        "cosign_tool",
        lambda *args: {"executableSha256": hashlib.sha256(binary.read_bytes()).hexdigest()},
    )

    def execute(command, **kwargs):
        calls.append(command)
        assert kwargs["env"]["PATH"] == "/usr/local/bin:/usr/bin:/bin"
        assert not any(
            k.startswith(("COSIGN_", "SIGSTORE_", "TRIVY_", "PYTHON")) for k in kwargs["env"]
        )
        assert command[command.index("--certificate-identity") + 1] == POLICY["identity"]
        assert command[command.index("--certificate-oidc-issuer") + 1] == POLICY["issuer"]
        assert not any(
            "insecure" in value or "regexp" in value or value == "--key" for value in command
        )
        return subprocess.CompletedProcess(command, 0, b"", b"")

    monkeypatch.setattr(tools["subprocess"], "run", execute)
    result = tools["verify_blob"](
        tmp_path, binary, artifact, signature, identity=POLICY["identity"], issuer=POLICY["issuer"]
    )
    assert (
        len(calls) == 1
        and result["verifiedBlobSha256"] == hashlib.sha256(artifact.read_bytes()).hexdigest()
    )


def test_signing_requires_a_job_token_before_touching_tools_or_artifacts(tmp_path):
    with pytest.raises(ValueError, match="job-scoped"):
        tools["sign_release"](tmp_path, tmp_path / "unused", context())
    assert not (tmp_path / "release-evidence").exists()


@pytest.fixture(scope="module")
def issuer_keys():
    return (
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
    )


def token_claims():
    now = int(datetime.now(UTC).timestamp())
    return {
        "iss": POLICY["issuer"],
        "aud": "sigstore",
        "sub": "project_path:example/certweaver:ref_type:tag:ref:v0.1.0",
        "iat": now,
        "nbf": now - 5,
        "exp": now + 600,
        "jti": "synthetic-unit-token-identifier",
        "project_id": "12345",
        "project_path": "example/certweaver",
        "job_project_id": "12345",
        "job_project_path": "example/certweaver",
        "job_id": "123456",
        "pipeline_id": "1234",
        "pipeline_source": "push",
        "sha": "a" * 40,
        "ci_config_sha": "a" * 40,
        "ci_config_ref_uri": POLICY["identity"].removeprefix("https://"),
        "ref": "v0.1.0",
        "ref_type": "tag",
        "ref_path": "refs/tags/v0.1.0",
        "ref_protected": "true",
        "environment": "release",
        "environment_protected": "true",
    }


@pytest.mark.parametrize(
    "change",
    [
        None,
        "wrong-signature",
        "wrong-algorithm",
        "unsigned",
        "wrong-issuer",
        "wrong-audience",
        "broad-audience",
        "expired",
        "future",
        "long-lived",
        "unprotected-ref",
        "unprotected-environment",
        "missing-protection",
        "numeric-true",
        "wrong-source",
        "wrong-config-sha",
        "wrong-config-uri",
        "wrong-project",
        "wrong-job-project",
        "wrong-job-path",
        "wrong-job",
        "wrong-pipeline",
        "wrong-ref",
        "wrong-subject",
        "unknown-key",
        "duplicate-key",
        "external-key-url",
        "duplicate-claim",
    ],
)
def test_rs256_issuer_signature_and_protected_claims_are_required(monkeypatch, issuer_keys, change):
    # Only the issuer key fetch is replaced with a local fixture. RSA signature,
    # audience/time validation and all claim comparisons execute normally.
    # This is not an issued GitLab token or a hosted integration rehearsal.
    private, other = issuer_keys
    claims, header = token_claims(), {"kid": "synthetic-issuer-key"}
    changes = {
        "wrong-issuer": ("iss", "https://other.example"),
        "wrong-audience": ("aud", "other"),
        "broad-audience": ("aud", ["sigstore", "other"]),
        "unprotected-ref": ("ref_protected", "false"),
        "unprotected-environment": ("environment_protected", "false"),
        "numeric-true": ("ref_protected", 1),
        "wrong-source": ("sha", "c" * 40),
        "wrong-config-sha": ("ci_config_sha", "c" * 40),
        "wrong-config-uri": (
            "ci_config_ref_uri",
            "gitlab.com/other/project//other.yml@refs/tags/v0.1.0",
        ),
        "wrong-project": ("project_id", "22222"),
        "wrong-job-project": ("job_project_id", "22222"),
        "wrong-job-path": ("job_project_path", "other/project"),
        "wrong-job": ("job_id", "987654"),
        "wrong-pipeline": ("pipeline_id", "9876"),
        "wrong-ref": ("ref_type", "branch"),
        "wrong-subject": ("sub", "project_path:other/project:ref_type:tag:ref:v0.1.0"),
    }
    if change in changes:
        name, value = changes[change]
        claims[name] = value
    elif change == "expired":
        claims.update(iat=claims["iat"] - 180, nbf=claims["nbf"] - 180, exp=claims["iat"] - 60)
    elif change == "future":
        claims.update(iat=claims["iat"] + 120, nbf=claims["nbf"] + 120)
    elif change == "long-lived":
        claims["exp"] = claims["iat"] + 3600
    elif change == "missing-protection":
        del claims["environment_protected"]
    elif change == "external-key-url":
        header["jku"] = "https://untrusted.example/keys"
    if change == "wrong-algorithm":
        encoded = jwt.encode(claims, b"s" * 32, algorithm="HS256", headers=header)
    elif change == "unsigned":
        encoded = jwt.encode(claims, "", algorithm="none", headers=header)
    elif change == "duplicate-claim":

        def segment(value):
            return base64.urlsafe_b64encode(value).rstrip(b"=")

        raw_header = segment(json.dumps({**header, "alg": "RS256", "typ": "JWT"}).encode())
        raw_payload = segment((json.dumps(claims)[:-1] + ',"sha":"' + "a" * 40 + '"}').encode())
        data = raw_header + b"." + raw_payload
        encoded = (
            data + b"." + segment(private.sign(data, padding.PKCS1v15(), hashes.SHA256()))
        ).decode()
    else:
        encoded = jwt.encode(
            claims,
            other if change == "wrong-signature" else private,
            algorithm="RS256",
            headers=header,
        )
    public = {
        **json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key())),
        "kid": header["kid"],
        "use": "sig",
        "alg": "RS256",
    }
    keys = (
        []
        if change == "unknown-key"
        else [public, public]
        if change == "duplicate-key"
        else [public]
    )
    requests = []
    monkeypatch.setitem(
        tools["authenticated_context"].__globals__,
        "fetch_gitlab_jwks",
        lambda: requests.append(True) or {"keys": keys},
    )
    environment = context()
    environment["SIGSTORE_ID_TOKEN"] = encoded
    if change:
        with pytest.raises((ValueError, jwt.PyJWTError)):
            tools["authenticated_context"](environment)
        if change in {"external-key-url", "wrong-algorithm", "unsigned", "duplicate-claim"}:
            assert requests == []
    else:
        assert tools["authenticated_context"](environment) == (POLICY, INVOCATION)


@pytest.mark.parametrize("failure_at", [None, "sign", "verify"])
def test_signing_orchestration_checks_reconstruction_and_post_signature_intake(
    tmp_path, monkeypatch, failure_at
):
    namespace = tools["sign_release"].__globals__
    evidence = tmp_path / "release-evidence"
    evidence.mkdir()
    events = []
    token = "synthetic-private-token-canary-never-sent"
    environment = context()
    environment["SIGSTORE_ID_TOKEN"] = token
    monkeypatch.setitem(namespace, "authenticated_context", lambda env: (POLICY, INVOCATION))
    monkeypatch.setitem(namespace, "cosign_tool", lambda *args: {})
    monkeypatch.setitem(
        namespace, "checked_subjects", lambda *args, **kwargs: copy.deepcopy(SUBJECTS)
    )
    monkeypatch.setitem(
        namespace,
        "helpers",
        lambda root: {
            "check-package-reproducibility": {
                "qualified_build": lambda *args, **kwargs: events.append("reconstruction")
            }
        },
    )

    def execute(command, **kwargs):
        events.append("sign")
        assert token not in " ".join(command)
        assert kwargs["env"]["SIGSTORE_ID_TOKEN"] == token
        assert set(kwargs["env"]) == {"PATH", "HOME", "XDG_CACHE_HOME", "SIGSTORE_ID_TOKEN"}
        assert "--fulcio-auth-flow" in command and "--key" not in command
        if failure_at != "sign":
            (evidence / tools["BUNDLE"]).write_text(
                "synthetic signing subprocess result", encoding="utf-8"
            )
        return subprocess.CompletedProcess(
            command, 1 if failure_at == "sign" else 0, b"", token.encode()
        )

    def intake(*args):
        events.append("verify")
        if failure_at == "verify":
            raise ValueError("Synthetic failed post-signature verification")
        return {"scope": "Mocked signing orchestration unit fixture"}

    monkeypatch.setattr(tools["subprocess"], "run", execute)
    monkeypatch.setitem(namespace, "verify_release", intake)
    if failure_at:
        with pytest.raises(ValueError):
            tools["sign_release"](tmp_path, tmp_path / "fixture-binary", environment)
    else:
        assert tools["sign_release"](tmp_path, tmp_path / "fixture-binary", environment)[
            "scope"
        ].startswith("Mocked")
    assert events == (
        ["reconstruction", "sign"] if failure_at == "sign" else ["reconstruction", "sign", "verify"]
    )
    assert token not in (evidence / tools["PROVENANCE"]).read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "change",
    [
        "source-removed",
        "source-optional",
        "source-wrong-commit",
        "source-incoming",
        "source-raw-report",
        "stage-order",
        "global-token",
        "builder-token",
        "signer-unprotected",
        "signer-wrong-audience",
        "signer-no-environment",
        "signer-incoming",
        "signer-skips-rebuild",
        "signer-skips-reproduce",
        "signer-signs-first",
        "signer-raw-artifacts",
        "consumer-token",
        "consumer-not-empty",
        "consumer-optional",
        "consumer-wrong-job",
        "consumer-untrusted-code",
        "consumer-allowed-failure",
    ],
)
def test_gitlab_release_mutations_fail_the_workflow_contract(tmp_path, change):
    root = project_root()
    shutil.copytree(root / ".github/workflows", tmp_path / ".github/workflows")
    shutil.copyfile(root / ".gitlab-ci.yml", tmp_path / ".gitlab-ci.yml")
    (tmp_path / "ci").mkdir()
    shutil.copyfile(
        root / "ci/gitlab-consumer-bootstrap.py", tmp_path / "ci/gitlab-consumer-bootstrap.py"
    )
    assert workflows["check_workflows"](tmp_path) == []
    value = workflows["load"](tmp_path / ".gitlab-ci.yml")
    source, signer, consumer = (value[k] for k in ["source-scan", "sign-release", "verify-release"])
    if change == "source-removed":
        del value["source-scan"]
    elif change == "source-optional":
        source["rules"] = [{"if": "false"}]
    elif change == "source-wrong-commit":
        source["script"][0] = source["script"][0].replace("$CI_COMMIT_SHA", "main")
    elif change == "source-incoming":
        source["dependencies"] = ["package"]
    elif change == "source-raw-report":
        source["artifacts"]["paths"].append(".certweaver/source-security/source-secrets.json")
    elif change == "stage-order":
        value["stages"] = ["test", "package", "sign", "security", "verify"]
    elif change == "global-token":
        value["default"]["id_tokens"] = signer["id_tokens"]
    elif change == "builder-token":
        value["package"]["id_tokens"] = signer["id_tokens"]
    elif change == "signer-unprotected":
        signer["rules"][0]["if"] = "$CI_COMMIT_TAG"
    elif change == "signer-wrong-audience":
        signer["id_tokens"]["SIGSTORE_ID_TOKEN"]["aud"] = "other"
    elif change == "signer-no-environment":
        signer.pop("environment")
    elif change == "signer-incoming":
        signer["dependencies"] = ["package"]
    elif change == "signer-skips-rebuild":
        signer["script"].pop(1)
    elif change == "signer-skips-reproduce":
        signer["script"].pop(2)
    elif change == "signer-signs-first":
        signer["script"].insert(0, signer["script"].pop())
    elif change == "signer-raw-artifacts":
        signer["artifacts"]["paths"].append(".certweaver/")
    elif change == "consumer-token":
        consumer["id_tokens"] = signer["id_tokens"]
    elif change == "consumer-not-empty":
        consumer["variables"]["GIT_STRATEGY"] = "fetch"
    elif change == "consumer-optional":
        consumer["needs"][0]["optional"] = "true"
    elif change == "consumer-wrong-job":
        consumer["needs"][0]["job"] = "package"
    elif change == "consumer-untrusted-code":
        consumer["script"] = ["python scripts/gitlab-release.py verify ."]
    elif change == "consumer-allowed-failure":
        consumer["allow_failure"] = "true"
    import yaml

    (tmp_path / ".gitlab-ci.yml").write_text(
        yaml.safe_dump(value, sort_keys=False), encoding="utf-8"
    )
    assert workflows["check_workflows"](tmp_path), change
