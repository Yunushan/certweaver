"""Sign and verify an exact GitLab.com release intake; never approves production."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import runpy
import ssl
import subprocess
import tempfile
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

import jwt
from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier

MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
PREDICATE = "https://slsa.dev/provenance/v1"
STATEMENT = "https://in-toto.io/Statement/v1"
ISSUER = "https://gitlab.com"
JWKS_URL = ISSUER + "/oauth/discovery/keys"
MAX_JSON = 2 * 1024 * 1024
MAX_BLOB = 2 * 1024 * 1024 * 1024
PROVENANCE = "gitlab-provenance.json"
BUNDLE = "gitlab-provenance.sigstore.json"


class ReleasePolicyError(ValueError):
    """A public, static policy diagnostic that contains no supplied claim values."""


def require(condition, message):
    if not condition:
        raise ReleasePolicyError(message)


def reject_nonfinite(value):
    raise ReleasePolicyError("Non-finite signature/provenance JSON numbers are unsupported")


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "Duplicate signature/provenance JSON key")
        result[key] = value
    return result


def regular(path, limit=MAX_JSON):
    require(
        not path.is_symlink() and path.is_file() and 0 < path.stat().st_size <= limit,
        "Expected one bounded nonempty regular release input",
    )
    with path.open("rb") as stream:
        value = stream.read(limit + 1)
    require(len(value) <= limit, "Release input exceeded its size bound")
    return value


def document(path):
    result = json.loads(regular(path), object_pairs_hook=pairs, parse_constant=reject_nonfinite)
    require(type(result) is dict, "Signature/provenance input must be an object")
    return result


def digest(path, limit=MAX_BLOB):
    require(
        not path.is_symlink() and path.is_file() and 0 < path.stat().st_size <= limit,
        "Release hash input must be a bounded regular file",
    )
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def policy(project, project_id, tag, commit):
    require(
        isinstance(project, str)
        and re.fullmatch(
            r"https://gitlab\.com/(?:[A-Za-z0-9_-][A-Za-z0-9_.-]*/)+[A-Za-z0-9_-][A-Za-z0-9_.-]*",
            project,
        )
        and not project.endswith(".git"),
        "Expected a canonical GitLab.com project URL",
    )
    require(
        isinstance(project_id, str) and re.fullmatch(r"[1-9][0-9]{0,19}", project_id),
        "Expected an independently supplied numeric GitLab project ID",
    )
    require(
        isinstance(tag, str)
        and re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[.+][A-Za-z0-9.]+)?", tag),
        "Expected an exact reviewed release tag",
    )
    require(
        isinstance(commit, str) and re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", commit),
        "Expected a full immutable source commit",
    )
    return {
        "project": project,
        "projectId": project_id,
        "tag": tag,
        "commit": commit,
        "identity": project + "//.gitlab-ci.yml@refs/tags/" + tag,
        "issuer": ISSUER,
    }


def ci_context(environment):
    require(
        all(
            environment.get(key) == value
            for key, value in {
                "CI": "true",
                "GITLAB_CI": "true",
                "CI_SERVER_URL": ISSUER,
                "CI_PIPELINE_SOURCE": "push",
                "CI_COMMIT_REF_PROTECTED": "true",
                "CI_CONFIG_PATH": ".gitlab-ci.yml",
                "CI_JOB_NAME": "sign-release",
                "CI_ENVIRONMENT_NAME": "release",
            }.items()
        ),
        "Signing requires the protected GitLab.com tag job and in-project configuration",
    )
    require(
        environment.get("CI_DEBUG_TRACE", "false").lower() != "true",
        "Signing refuses debug tracing",
    )
    selected = policy(
        environment.get("CI_PROJECT_URL"),
        environment.get("CI_PROJECT_ID"),
        environment.get("CI_COMMIT_TAG"),
        environment.get("CI_COMMIT_SHA"),
    )
    require(
        selected["project"] == ISSUER + "/" + environment.get("CI_PROJECT_PATH", ""),
        "GitLab project URL/path mismatch",
    )
    for name in ["CI_JOB_ID", "CI_PIPELINE_ID"]:
        require(
            re.fullmatch(r"[1-9][0-9]{0,19}", environment.get(name, "")),
            "Signing requires concrete GitLab execution identities",
        )
    return selected, selected["project"] + "/-/jobs/" + environment["CI_JOB_ID"]


class NoKeyRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError("GitLab issuer key acquisition cannot redirect")


def fetch_gitlab_jwks():
    # Use the runner image's compiled-in system CA paths, without accepting
    # SSL_CERT_FILE/SSL_CERT_DIR or proxy overrides from pipeline variables.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    paths = ssl.get_default_verify_paths()
    context.load_verify_locations(cafile=paths.openssl_cafile, capath=paths.openssl_capath)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        NoKeyRedirects(),
    )
    request = urllib.request.Request(JWKS_URL, headers={"User-Agent": "CertWeaver-release-intake"})
    with opener.open(request, timeout=20) as response:
        require(response.geturl() == JWKS_URL, "Unexpected GitLab issuer key origin")
        payload = response.read(1024 * 1024 + 1)
    require(len(payload) <= 1024 * 1024, "GitLab issuer key response exceeds its size bound")
    value = json.loads(payload, object_pairs_hook=pairs, parse_constant=reject_nonfinite)
    require(
        type(value) is dict
        and isinstance(value.get("keys"), list)
        and 0 < len(value["keys"]) <= 100,
        "Invalid GitLab issuer key set",
    )
    return value


def authenticated_context(environment):
    selected, invocation = ci_context(environment)
    token = environment.get("SIGSTORE_ID_TOKEN")
    require(
        isinstance(token, str) and 0 < len(token) <= 64 * 1024,
        "Signing requires the job-scoped GitLab Sigstore ID token",
    )
    parts = token.split(".")
    require(
        len(parts) == 3 and all(re.fullmatch(r"[A-Za-z0-9_-]+", p) for p in parts),
        "Signing requires a canonical compact ID token",
    )

    def decode(part):
        return json.loads(
            base64.b64decode(part + "=" * (-len(part) % 4), altchars=b"-_", validate=True),
            object_pairs_hook=pairs,
            parse_constant=reject_nonfinite,
        )

    header, payload = decode(parts[0]), decode(parts[1])
    require(
        type(header) is dict
        and set(header) <= {"alg", "kid", "typ"}
        and header.get("alg") == "RS256"
        and header.get("typ", "JWT") == "JWT"
        and isinstance(header.get("kid"), str)
        and 0 < len(header["kid"]) <= 256
        and type(payload) is dict,
        "Unexpected ID token algorithm, header or payload",
    )
    keys = [
        value
        for value in fetch_gitlab_jwks()["keys"]
        if type(value) is dict and value.get("kid") == header["kid"]
    ]
    require(
        len(keys) == 1
        and keys[0].get("kty") == "RSA"
        and keys[0].get("alg", "RS256") == "RS256"
        and keys[0].get("use", "sig") == "sig",
        "ID token issuer key is absent, ambiguous or inappropriate",
    )
    key = jwt.PyJWK.from_dict(keys[0], algorithm="RS256").key
    require(key.key_size >= 2048, "ID token issuer RSA key is too small")
    claims = jwt.decode(
        token,
        key,
        algorithms=["RS256"],
        issuer=ISSUER,
        audience="sigstore",
        leeway=30,
        options={"require": ["iss", "sub", "aud", "exp", "iat", "nbf", "jti"]},
    )
    require(
        claims == payload
        and claims["aud"] == "sigstore"
        and all(type(claims.get(k)) is int for k in ["exp", "iat", "nbf"])
        and 0 < claims["exp"] - claims["iat"] <= 1800
        and claims["nbf"] <= claims["iat"]
        and isinstance(claims["jti"], str)
        and 0 < len(claims["jti"]) <= 256,
        "Invalid ID token chronology, audience or identifier",
    )
    path = selected["project"].removeprefix(ISSUER + "/")
    expected = {
        "sub": f"project_path:{path}:ref_type:tag:ref:{selected['tag']}",
        "project_path": path,
        "job_project_path": path,
        "sha": selected["commit"],
        "ref_type": "tag",
        "ref": selected["tag"],
        "ref_path": "refs/tags/" + selected["tag"],
        "pipeline_source": "push",
        "ci_config_ref_uri": selected["identity"].removeprefix("https://"),
        "ci_config_sha": selected["commit"],
        "environment": "release",
    }
    require(
        all(claims.get(k) == v for k, v in expected.items()),
        "Authenticated ID token source/configuration/ref claims differ from the signing context",
    )
    for name, expected_id in [
        ("project_id", selected["projectId"]),
        ("job_project_id", selected["projectId"]),
        ("job_id", environment["CI_JOB_ID"]),
        ("pipeline_id", environment["CI_PIPELINE_ID"]),
    ]:
        require(
            type(claims.get(name)) in {str, int} and str(claims[name]) == expected_id,
            "Authenticated ID token project/execution identity mismatch",
        )
    for name in ["ref_protected", "environment_protected"]:
        require(
            claims.get(name) is True or claims.get(name) == "true",
            "Authenticated ID token must attest a protected tag and protected release environment",
        )
    return selected, invocation


def certificate(bundle):
    require(
        bundle.get("mediaType") == MEDIA_TYPE and "messageSignature" in bundle,
        "Only the reviewed v0.3 certificate-backed Sigstore blob bundle is accepted",
    )
    material = bundle.get("verificationMaterial")
    require(
        type(material) is dict
        and type(material.get("certificate")) is dict
        and set(material["certificate"]) == {"rawBytes"}
        and "x509CertificateChain" not in material
        and material.get("tlogEntries"),
        "A leaf signing certificate and transparency proof are mandatory",
    )
    value = base64.b64decode(material["certificate"]["rawBytes"], validate=True)
    require(0 < len(value) <= 64 * 1024, "Signing certificate exceeded its size bound")
    return x509.load_der_x509_certificate(value), hashlib.sha256(value).hexdigest()


def utf8_extension(value):
    """Encode expected DER UTF8String bytes; no untrusted ASN.1 parsing is needed."""
    payload = value.encode("utf-8")
    length = len(payload)
    if length < 128:
        return bytes([12, length]) + payload
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([12, 128 + len(encoded)]) + encoded + payload


def certificate_policy(cert, selected, invocation):
    algorithm = "sha1" if len(selected["commit"]) == 40 else "sha256"
    commit_values = {selected["commit"], algorithm + ":" + selected["commit"]}
    expected = {
        8: {ISSUER},
        9: {selected["identity"]},
        10: commit_values,
        12: {selected["project"]},
        13: commit_values,
        14: {"refs/tags/" + selected["tag"]},
        15: {selected["projectId"]},
        18: {selected["identity"]},
        19: commit_values,
        20: {"push"},
        21: {invocation},
        23: {"release"},
    }
    for number, values in expected.items():
        extension = cert.extensions.get_extension_for_oid(
            ObjectIdentifier("1.3.6.1.4.1.57264.1." + str(number))
        ).value
        require(
            isinstance(extension, x509.UnrecognizedExtension)
            and extension.value in {utf8_extension(value) for value in values},
            "Authenticated certificate source/project/configuration/execution policy mismatch",
        )


def cosign_tool(root, binary):
    tools = runpy.run_path(str(root / "scripts/install-ci-tool.py"))
    expected = tools["tool_record"](root, "cosign")
    require(
        not binary.is_symlink()
        and binary.is_file()
        and digest(binary) == expected["executableSha256"],
        "Cosign is not the pinned executable",
    )
    return expected


def tool_environment(home, *, token=None):
    # Public production Sigstore/TUF defaults are selected by the pinned binary.
    # No caller-provided trust root, alternate endpoints, ambient identity,
    # Python path or Cosign/Sigstore configuration participates.
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": str(home),
        "XDG_CACHE_HOME": str(home / "cache"),
    }
    if token is not None:
        env["SIGSTORE_ID_TOKEN"] = token
    return env


def verify_blob(root, binary, blob, bundle_path, *, identity, issuer):
    tool = cosign_tool(root, binary)
    bundle_bytes = regular(bundle_path)
    parsed = json.loads(bundle_bytes, object_pairs_hook=pairs, parse_constant=reject_nonfinite)
    certificate(parsed)  # Reject legacy/public-key bundles before invoking Cosign.
    require(
        not blob.is_symlink() and blob.is_file() and 0 < blob.stat().st_size <= MAX_BLOB,
        "Invalid signed blob",
    )
    with tempfile.TemporaryDirectory(prefix="certweaver-cosign-verify-") as temporary:
        work = Path(temporary)
        trusted_bundle = work / "bundle.json"
        trusted_bundle.write_bytes(bundle_bytes)
        before = digest(blob)
        result = subprocess.run(
            [
                str(binary),
                "verify-blob",
                "--bundle",
                str(trusted_bundle),
                "--certificate-identity",
                identity,
                "--certificate-oidc-issuer",
                issuer,
                "--timeout",
                "2m",
                str(blob),
            ],
            cwd=work,
            env=tool_environment(work),
            capture_output=True,
            timeout=150,
            check=False,
        )
        require(
            result.returncode == 0 and digest(blob) == before,
            "Cosign keyless signature/identity/transparency verification failed",
        )
        roots = {
            p.relative_to(work).as_posix(): digest(p, MAX_JSON)
            for p in sorted(work.rglob("*.json"))
            if p.is_file() and p != trusted_bundle
        }
    return {
        "cosignExecutableSha256": tool["executableSha256"],
        "bundleSha256": hashlib.sha256(bundle_bytes).hexdigest(),
        "verifiedBlobSha256": before,
        "identity": identity,
        "issuer": issuer,
        "publicTrustMetadataSha256": roots,
    }


def helpers(root):
    return {
        name: runpy.run_path(str(root / "scripts" / (name + ".py")))
        for name in ["check-release", "release-evidence", "check-package-reproducibility"]
    }


def checked_subjects(root, candidate, selected, *, signed):
    require(not candidate.is_symlink() and candidate.is_dir(), "Invalid candidate directory")
    distribution, evidence = candidate / "dist", candidate / "release-evidence"
    require(
        not distribution.is_symlink() and not evidence.is_symlink() and evidence.is_dir(),
        "Candidate directories must not be links",
    )
    expected = {"qualification.json", PROVENANCE, BUNDLE} if signed else {"qualification.json"}
    require(
        {p.name for p in evidence.iterdir()} == expected,
        "Release evidence directory contains missing or unexpected files",
    )
    functions = helpers(root)
    errors = functions["check-release"]["check_release"](
        distribution, tag=selected["tag"], commit=selected["commit"], root=root
    )
    require(not errors, "Candidate release identity/content verification failed")
    functions["release-evidence"]["verify_record"](
        functions["release-evidence"]["document"](evidence / "qualification.json"),
        directory=distribution,
        root=root,
        tag=selected["tag"],
        commit=selected["commit"],
        now=datetime.now(UTC),
    )
    paths = [*sorted(distribution.iterdir()), evidence / "qualification.json"]
    return sorted(
        [
            {"name": p.relative_to(candidate).as_posix(), "digest": {"sha256": digest(p)}}
            for p in paths
        ],
        key=lambda item: item["name"],
    )


def statement(selected, invocation, subjects):
    project, commit, tag = selected["project"], selected["commit"], selected["tag"]
    algorithm = "sha1" if len(commit) == 40 else "sha256"
    return {
        "_type": STATEMENT,
        "subject": subjects,
        "predicateType": PREDICATE,
        "predicate": {
            "buildDefinition": {
                "buildType": project + "/-/blob/" + commit + "/.gitlab-ci.yml#sign-release",
                "externalParameters": {
                    "source": {
                        "uri": project + ".git",
                        "digest": {algorithm: commit},
                        "ref": "refs/tags/" + tag,
                    },
                    "projectId": selected["projectId"],
                    "releaseTag": tag,
                },
                "internalParameters": {
                    "ciConfigPath": ".gitlab-ci.yml",
                    "identityPolicy": "gitlab-protected-release-v1",
                    "refProtected": True,
                    "environmentProtected": True,
                },
                "resolvedDependencies": [
                    {"uri": "git+" + project + ".git", "digest": {algorithm: commit}}
                ],
            },
            "runDetails": {
                "builder": {"id": selected["identity"]},
                "metadata": {"invocationId": invocation},
            },
        },
    }


def verify_release(root, candidate, binary, selected):
    evidence = candidate / "release-evidence"
    provenance_bytes = regular(evidence / PROVENANCE)
    bundle_bytes = regular(evidence / BUNDLE)
    # Verify a private copy of the exact manifest bytes subsequently interpreted.
    with tempfile.TemporaryDirectory(prefix="certweaver-gitlab-statement-") as temporary:
        blob = Path(temporary) / "provenance.json"
        bundle = Path(temporary) / "bundle.json"
        blob.write_bytes(provenance_bytes)
        bundle.write_bytes(bundle_bytes)
        crypto = verify_blob(
            root, binary, blob, bundle, identity=selected["identity"], issuer=ISSUER
        )
    parsed = json.loads(provenance_bytes, object_pairs_hook=pairs, parse_constant=reject_nonfinite)
    invocation = parsed["predicate"]["runDetails"]["metadata"]["invocationId"]
    require(
        isinstance(invocation, str)
        and re.fullmatch(re.escape(selected["project"]) + r"/-/jobs/[1-9][0-9]{0,19}", invocation),
        "Expected a concrete signer job in the trusted project",
    )
    cert, certificate_digest = certificate(
        json.loads(bundle_bytes, object_pairs_hook=pairs, parse_constant=reject_nonfinite)
    )
    certificate_policy(cert, selected, invocation)
    subjects = checked_subjects(root, candidate, selected, signed=True)
    require(
        parsed == statement(selected, invocation, subjects),
        "Signed provenance does not match exact source, project, build policy and all subjects",
    )
    require(
        digest(evidence / PROVENANCE) == hashlib.sha256(provenance_bytes).hexdigest(),
        "Provenance changed during intake",
    )
    require(
        digest(evidence / BUNDLE) == hashlib.sha256(bundle_bytes).hexdigest(),
        "Signature bundle changed during intake",
    )
    return {
        "status": "GITLAB_RELEASE_INTAKE_VERIFIED_NOT_PRODUCTION_APPROVAL",
        "scope": "Cryptographic release intake and current qualification; no hosted-job/protection "
        "audit, SLSA level, independent review or production approval inferred",
        "expectedPolicy": selected,
        "invocationId": invocation,
        "subjects": subjects,
        "certificateSha256": certificate_digest,
        "signatureVerification": crypto,
    }


def sign_release(root, binary, environment):
    selected, invocation = authenticated_context(environment)
    token = environment.get("SIGSTORE_ID_TOKEN")
    require(
        isinstance(token, str) and token and len(token) <= 64 * 1024,
        "Signing requires the job-scoped GitLab Sigstore ID token",
    )
    cosign_tool(root, binary)
    subjects = checked_subjects(root, root, selected, signed=False)
    helpers(root)["check-package-reproducibility"]["qualified_build"](
        root, root / "dist", commit=selected["commit"]
    )
    provenance = root / "release-evidence" / PROVENANCE
    with provenance.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(statement(selected, invocation, subjects), stream, indent=2)
        stream.write("\n")
    bundle = root / "release-evidence" / BUNDLE
    with tempfile.TemporaryDirectory(prefix="certweaver-cosign-sign-") as temporary:
        result = subprocess.run(
            [
                str(binary),
                "sign-blob",
                "--yes",
                "--fulcio-auth-flow",
                "token",
                "--bundle",
                str(bundle),
                "--timeout",
                "2m",
                str(provenance),
            ],
            cwd=Path(temporary),
            env=tool_environment(Path(temporary), token=token),
            capture_output=True,
            timeout=150,
            check=False,
        )
    require(result.returncode == 0, "GitLab keyless signing failed")
    return verify_release(root, root, binary, selected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["context", "sign", "verify"])
    parser.add_argument("directory", nargs="?", type=Path)
    parser.add_argument("--cosign", type=Path)
    parser.add_argument("--project-url")
    parser.add_argument("--project-id")
    parser.add_argument("--tag")
    parser.add_argument("--commit")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        if args.operation == "context":
            selected, _ = authenticated_context(os.environ)
            helpers(root)["check-release"]["release_version"](selected["tag"], root)
            print(
                "Authenticated protected GitLab.com signing context validated; "
                "no token value emitted"
            )
            return 0
        require(args.cosign is not None, "The pinned Cosign executable is required")
        if args.operation == "sign":
            result = sign_release(root, args.cosign.absolute(), os.environ)
        else:
            require(args.directory is not None, "The candidate directory is required")
            selected = policy(args.project_url, args.project_id, args.tag, args.commit)
            result = verify_release(
                root, args.directory.absolute(), args.cosign.absolute(), selected
            )
        if args.output:
            require(not args.output.is_symlink(), "Verification output cannot be a link")
            with args.output.open("x", encoding="utf-8", newline="\n") as stream:
                json.dump(result, stream, indent=2)
                stream.write("\n")
        print(
            "GitLab signature, exact subject/source and current qualification verified; "
            "production approval not inferred"
        )
        return 0
    except ReleasePolicyError as exc:
        print("ERROR: GitLab release policy rejected: " + str(exc))
        return 1
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        x509.ExtensionNotFound,
        x509.DuplicateExtension,
        jwt.PyJWTError,
        subprocess.SubprocessError,
    ) as exc:
        # Neither ID tokens, arbitrary certificate claims nor subprocess stderr
        # belong in a public CI trace or a retained derived evidence record.
        print("ERROR: GitLab release operation failed (" + type(exc).__name__ + ")")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
