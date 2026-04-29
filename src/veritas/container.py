"""Pull, verify, and extract files from container images."""

import json
import subprocess
import tarfile
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
        self._pulled = {}  # image_ref -> (TemporaryDirectory, img_dir Path)

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
        """Pull the image locally using skopeo copy."""
        if image_ref in self._pulled:
            return
        tmpdir = tempfile.TemporaryDirectory()
        img_dir = Path(tmpdir.name) / "image"
        cmd = ["skopeo", "copy", f"docker://{image_ref}", f"dir:{img_dir}"]
        cmd.extend(self._auth_args())
        self._run(cmd)
        self._pulled[image_ref] = (tmpdir, img_dir)

    def extract_file(self, image_ref, container_path):
        """Extract a file from the image and return its contents as text."""
        path = self._extract_to_tmp(image_ref, container_path)
        with open(path) as f:
            return f.read()

    def extract_to_dir(self, image_ref, container_path, dest_dir):
        """Extract a file from the image to a destination directory."""
        dest = Path(dest_dir) / Path(container_path).name
        self._extract_to_path(image_ref, container_path, dest)
        return dest

    def _extract_to_tmp(self, image_ref, container_path):
        """Extract a file from the image to a temp file and return its path."""
        tmp = tempfile.NamedTemporaryFile(suffix=Path(container_path).suffix, delete=False)
        tmp.close()
        self._extract_to_path(image_ref, container_path, Path(tmp.name))
        return tmp.name

    def _get_image_dir(self, image_ref):
        """Return the local image directory, pulling first if needed."""
        if image_ref not in self._pulled:
            self.pull(image_ref)
        return self._pulled[image_ref][1]

    def _extract_to_path(self, image_ref, container_path, dest_path):
        """Extract a single file from the image to dest_path."""
        img_dir = self._get_image_dir(image_ref)
        self._extract_from_image_dir(img_dir, container_path, dest_path)

    def _extract_from_image_dir(self, img_dir, container_path, dest_path):
        """Extract a file from a skopeo dir: image directory to dest_path."""
        img_dir = Path(img_dir)
        with open(img_dir / "manifest.json") as f:
            manifest = json.load(f)

        # Tar entries use relative paths without a leading slash
        tar_path = container_path.lstrip("/")
        last_found = None  # (layer_file, entry_name_in_tar)

        for layer in manifest["layers"]:
            # skopeo dir: names layer files by the hex digest only (no "sha256:" prefix)
            layer_file = img_dir / layer["digest"].split(":", 1)[-1]
            with tarfile.open(str(layer_file), "r:*") as tf:
                # Build a lookup normalised to no leading "./"
                names = {n.lstrip("./"): n for n in tf.getnames()}

                # A whiteout entry signals the file was deleted in this layer
                parent = str(Path(tar_path).parent).lstrip("./")
                whiteout = f"{parent}/.wh.{Path(tar_path).name}" if parent not in ("", ".") else f".wh.{Path(tar_path).name}"
                if whiteout.lstrip("./") in names:
                    last_found = None
                    continue

                if tar_path in names:
                    last_found = (layer_file, names[tar_path])

        if last_found is None:
            raise FileNotFoundError(f"{container_path} not found in image")

        layer_file, entry_name = last_found
        with tarfile.open(str(layer_file), "r:*") as tf:
            with tf.extractfile(tf.getmember(entry_name)) as src:
                Path(dest_path).write_bytes(src.read())

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
