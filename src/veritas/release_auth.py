"""Authenticate OpenShift release images against Red Hat's signing key.

``oc adm release info --verify`` checks that a release payload is internally
consistent (the referenced component images match the release manifest), but it
does **not** prove who published the release: a registry that serves a
different-but-self-consistent payload under the same tag would pass. Veritas
runs before deployment, on a host that may be compromised, and turns the
release's contents into *trusted* reference values, so it must authenticate the
publisher first.

OpenShift release images are signed with Red Hat's "simple signing" (atomic
container signature) scheme, the same one the Cluster Version Operator verifies
in-cluster (see github.com/openshift/cluster-update-keys):

* a detached GPG signature over a claim binding an image **digest** to a
  **docker-reference**, signed by "Red Hat, Inc. (release key 2)"
  (fingerprint ``567E347AD0044ADE55BA8A5F199E2F91FD431D51``);
* published in a public signature store, addressed by the image digest:
  ``<store>/sha256=<digest>/signature-<n>``.

This is a different mechanism from the cosign/Rekor signatures on the Azure
dm-verity image (see ``veritas.container``), so it needs its own verifier.

The authenticated trust chain this module anchors:

    Red Hat release key (vendored, fingerprint-pinned)
      -> GPG-signed release claim
      -> release image digest  (bound by the signature)
      -> rhel-coreos-extensions image  (resolved from the digest)
      -> kata-containers / edk2-ovmf RPMs  (GPG-signed by the same key)
      -> configuration.toml  (inside the signed RPM)
      -> veritas reference values

The public key ships with veritas (``data/redhat-release-verifier.gpg``) so
verification never bootstraps trust from a key downloaded at run time. Its
fingerprint is checked against the pinned constant before use, and
``skopeo standalone-verify`` is always given that explicit fingerprint, so only
that one key is ever trusted.
"""

from __future__ import annotations

import hashlib
import json
import logging
import subprocess
import tempfile
import urllib.error
import urllib.request
from importlib import resources
from pathlib import Path

log = logging.getLogger(__name__)

# "Red Hat, Inc. (release key 2) <security@redhat.com>". The same key signs
# OpenShift release images and the RPMs inside the extensions image. Pinned in
# source; the vendored key file is checked against it before use.
REDHAT_RELEASE_KEY_FINGERPRINT = "567E347AD0044ADE55BA8A5F199E2F91FD431D51"

# Public signature stores, in order of preference. Addressed by image digest:
# <store>/sha256=<hexdigest>/signature-<n>. These mirror what
# cluster-update-keys configures for the Cluster Version Operator.
DEFAULT_SIGNATURE_STORES = (
    "https://mirror.openshift.com/pub/openshift-v4/signatures/openshift/release",
    "https://storage.googleapis.com/openshift-release/official/signatures/openshift/release",
)

# Upper bound on signature-<n> probing per store (there are only ever a few).
MAX_SIGNATURES_PER_STORE = 10

_VENDORED_KEY = ("veritas.data", "redhat-release-verifier.gpg")


class ReleaseAuthError(RuntimeError):
    """The release publisher could not be cryptographically authenticated."""


def _fetch_url(url: str, timeout: int = 60) -> bytes | None:
    """Return the bytes at ``url`` (http(s) or file://), or None if absent.

    Absent (HTTP 404 / missing file) returns None so the caller can try the
    next signature index or store. Any other failure raises.
    """
    if url.startswith("file://"):
        path = Path(url[len("file://"):])
        if not path.exists():
            return None
        return path.read_bytes()
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 (http(s)/file only, validated)
            return resp.read()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise ReleaseAuthError(f"fetching {url} failed: HTTP {e.code}") from e
    except (urllib.error.URLError, TimeoutError) as e:
        raise ReleaseAuthError(f"fetching {url} failed: {e}") from e


class ReleaseAuthenticator:
    """Verify OpenShift release-image publisher signatures and RPM signatures."""

    def __init__(self, authfile: str | None = None,
                 signature_stores: tuple[str, ...] | list[str] | None = None,
                 public_key_file: str | None = None,
                 key_fingerprint: str = REDHAT_RELEASE_KEY_FINGERPRINT):
        self.authfile = authfile
        self.signature_stores = tuple(signature_stores or DEFAULT_SIGNATURE_STORES)
        self.key_fingerprint = key_fingerprint.replace(" ", "").upper()
        self._public_key_file = public_key_file
        self._key_ctx = None  # keeps the importlib.resources handle alive

    # -- trusted public key ------------------------------------------------

    def public_key_file(self) -> str:
        """Path to the trusted Red Hat key, verified to match the pinned FPR.

        Uses the caller-supplied key if given (disconnected override), else the
        key vendored in the package. Either way the key's fingerprint must equal
        the pinned fingerprint, so a swapped key file cannot widen trust.
        """
        if self._public_key_file is None:
            ctx = resources.as_file(resources.files(_VENDORED_KEY[0]) / _VENDORED_KEY[1])
            self._key_ctx = ctx
            self._public_key_file = str(ctx.__enter__())
        self._assert_key_fingerprint(self._public_key_file)
        return self._public_key_file

    def _assert_key_fingerprint(self, key_file: str):
        fprs = self._gpg_fingerprints(key_file)
        if self.key_fingerprint not in fprs:
            raise ReleaseAuthError(
                f"trusted key {key_file} does not contain the expected Red Hat "
                f"release key {self.key_fingerprint} (found: {', '.join(fprs) or 'none'})"
            )

    @staticmethod
    def _gpg_fingerprints(key_file: str) -> list[str]:
        result = subprocess.run(
            ["gpg", "--show-keys", "--with-colons", key_file],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise ReleaseAuthError(f"cannot read key {key_file}: {result.stderr.strip()}")
        return [line.split(":")[9] for line in result.stdout.splitlines()
                if line.startswith("fpr:")]

    # -- release image signature ------------------------------------------

    def verify_release(self, repo: str, tag: str) -> str:
        """Authenticate ``repo:tag`` and return its verified image digest.

        Fetches the image manifest, binds it to a digest, then requires a
        signature for that digest — signed by the pinned Red Hat key and
        claiming this exact ``repo:tag`` — from a signature store. Fails closed
        if no such signature can be found and verified.
        """
        reference = f"{repo}:{tag}"
        manifest = self._fetch_manifest(reference)
        digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
        log.info("Resolved %s to %s", reference, digest)

        key_file = self.public_key_file()
        digest_path = digest.replace(":", "=")

        with tempfile.NamedTemporaryFile(suffix=".manifest", delete=True) as mf:
            mf.write(manifest)
            mf.flush()
            errors = []
            for store in self.signature_stores:
                for n in range(1, MAX_SIGNATURES_PER_STORE + 1):
                    url = f"{store.rstrip('/')}/{digest_path}/signature-{n}"
                    sig = _fetch_url(url)
                    if sig is None:
                        break  # no signature-n here; move to the next store
                    ok, detail = self._standalone_verify(mf.name, reference, sig, key_file)
                    if ok:
                        log.info("Release publisher authenticated: %s (%s), key %s",
                                 reference, digest, self.key_fingerprint)
                        return digest
                    errors.append(f"{url}: {detail}")

        hint = "; ".join(errors) if errors else \
            "no signature found in any store (stores: " + ", ".join(self.signature_stores) + ")"
        raise ReleaseAuthError(
            f"could not authenticate release publisher for {reference} ({digest}): {hint}"
        )

    def _fetch_manifest(self, reference: str) -> bytes:
        """Return the raw image manifest bytes for a tag reference."""
        cmd = ["skopeo", "inspect", "--raw", f"docker://{reference}"]
        if self.authfile:
            cmd += ["--authfile", self.authfile]
        result = subprocess.run(cmd, capture_output=True)
        if result.returncode != 0:
            raise ReleaseAuthError(
                f"cannot fetch manifest for {reference}: "
                f"{result.stderr.decode(errors='replace').strip()}"
            )
        # A multi-arch tag would return an image index, not a signed leaf
        # manifest; OCP x86_64 release tags are single manifests.
        try:
            media = json.loads(result.stdout).get("mediaType", "")
        except json.JSONDecodeError:
            media = ""
        if "manifest.list" in media or "image.index" in media:
            raise ReleaseAuthError(
                f"{reference} is a multi-arch index ({media}); expected a single "
                "release manifest to authenticate"
            )
        return result.stdout

    def _standalone_verify(self, manifest_file: str, reference: str,
                           signature: bytes, key_file: str) -> tuple[bool, str]:
        """Run ``skopeo standalone-verify`` for one signature.

        Returns (verified, detail). ``verified`` is True only when the GPG
        signature is valid under the pinned key *and* its embedded digest and
        docker-reference match the manifest and ``reference``.
        """
        with tempfile.NamedTemporaryFile(suffix=".sig", delete=True) as sf:
            sf.write(signature)
            sf.flush()
            result = subprocess.run(
                ["skopeo", "standalone-verify", manifest_file, reference,
                 self.key_fingerprint, sf.name, "--public-key-file", key_file],
                capture_output=True, text=True,
            )
        if result.returncode == 0:
            return True, result.stdout.strip()
        return False, result.stderr.strip() or result.stdout.strip()

    # -- RPM signature -----------------------------------------------------

    def verify_rpm(self, rpm_path: str | Path):
        """Verify an RPM is signed by the pinned Red Hat key. Fail closed.

        Guards the kata/edk2 RPMs regardless of where they came from (a fresh
        digest-pinned pull or the local extensions cache), so a tampered or
        unsigned RPM in the cache cannot feed forged configuration into the
        measurements. Runs fully offline against the vendored key.
        """
        rpm_path = Path(rpm_path)
        key_file = self.public_key_file()
        with tempfile.TemporaryDirectory() as dbdir:
            imp = subprocess.run(
                ["rpm", "--dbpath", dbdir, "--import", key_file],
                capture_output=True, text=True,
            )
            if imp.returncode != 0:
                raise ReleaseAuthError(
                    f"cannot import trusted key into rpm keyring: {imp.stderr.strip()}"
                )
            check = subprocess.run(
                ["rpm", "--dbpath", dbdir, "--checksig", str(rpm_path)],
                capture_output=True, text=True,
            )
        out = (check.stdout + check.stderr).strip()
        # With only the Red Hat key imported, "signatures OK" means the RPM
        # carries a valid signature by that key. An unsigned RPM reports
        # "digests OK" (no "signatures") and would otherwise pass with exit 0,
        # so the presence of "signatures ok" is required explicitly.
        if check.returncode != 0 or "signatures ok" not in out.lower():
            raise ReleaseAuthError(
                f"RPM signature verification failed for {rpm_path.name}: {out}"
            )
        log.info("RPM signature verified (%s): %s", self.key_fingerprint, rpm_path.name)
