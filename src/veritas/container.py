"""Pull, verify, and extract files from container images."""

import json
import subprocess
import tempfile
from pathlib import Path


class ContainerImage:
    """Pull and extract files from a container image."""

    COSIGN_PUB_KEY_URL = "https://security.access.redhat.com/data/63405576.txt"
    REKOR_PUB_KEY_URL = "https://tuf-default.apps.rosa.rekor-prod.2jng.p3.openshiftapps.com/targets/rekor.pub"
    REKOR_URL = "https://rekor-server-default.apps.rosa.rekor-prod.2jng.p3.openshiftapps.com"

    def __init__(self, repository, tag="latest", authfile=None):
        self.repository = repository
        self.tag = tag
        self.authfile = authfile

    @property
    def reference(self):
        """Return the tag-based image reference."""
        return f"{self.repository}:{self.tag}"

    def get_digest(self):
        """Query the registry and return the image digest."""
        cmd = ["skopeo", "inspect", f"docker://{self.reference}"]
        cmd.extend(self._auth_args())
        out = self._run(cmd)
        return json.loads(out)["Digest"]

    def get_pinned_reference(self):
        """Return a digest-pinned image reference."""
        digest = self.get_digest()
        return f"{self.repository}@{digest}"

    def verify(self, image_ref):
        """Verify the image signature with Cosign and Rekor."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cosign_key = Path(tmpdir) / "cosign-pub-key.pem"
            rekor_key = Path(tmpdir) / "rekor.pub"
            self._run(["curl", "-sL", self.COSIGN_PUB_KEY_URL, "-o", str(cosign_key)])
            self._run(["curl", "-sL", self.REKOR_PUB_KEY_URL, "-o", str(rekor_key)])
            self._run([
                "cosign", "verify",
                "--key", str(cosign_key),
                "--rekor-url", self.REKOR_URL,
                image_ref,
            ], env={"SIGSTORE_REKOR_PUBLIC_KEY": str(rekor_key)})

    def pull(self, image_ref):
        """Pull the image locally."""
        cmd = ["podman", "pull", image_ref]
        cmd.extend(self._auth_args())
        self._run(cmd)

    def extract_file(self, image_ref, container_path):
        """Extract a file from the image and return its contents as text."""
        path = self._extract_to_tmp(image_ref, container_path)
        with open(path) as f:
            return f.read()

    def extract_to_dir(self, image_ref, container_path, dest_dir):
        """Extract a file from the image to a destination directory."""
        dest = Path(dest_dir) / Path(container_path).name
        cid = self._run(["podman", "create", "--entrypoint", "/bin/true", image_ref])
        try:
            self._run(["podman", "cp", f"{cid}:{container_path}", str(dest)])
        finally:
            self._run(["podman", "rm", cid])
        return dest

    def _extract_to_tmp(self, image_ref, container_path):
        """Extract a file from the image to a temp file and return its path."""
        cid = self._run(["podman", "create", "--entrypoint", "/bin/true", image_ref])
        try:
            tmp = tempfile.NamedTemporaryFile(suffix=Path(container_path).suffix, delete=False)
            self._run(["podman", "cp", f"{cid}:{container_path}", tmp.name])
            return tmp.name
        finally:
            self._run(["podman", "rm", cid])

    def _auth_args(self):
        if self.authfile:
            return ["--authfile", self.authfile]
        return []

    @staticmethod
    def _run(cmd, env=None):
        import os
        run_env = {**os.environ, **env} if env else None
        result = subprocess.run(cmd, capture_output=True, text=True, env=run_env)
        if result.returncode != 0:
            raise RuntimeError(f"{' '.join(cmd)}\n{result.stderr}")
        return result.stdout.strip()
