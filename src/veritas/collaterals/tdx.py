"""Intel TDX collateral (TCB info, QE identity and CRLs from Intel PCS)."""

import json
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

SECRET_NAME = "tdx-collateral"
MOUNT_DIR = "/opt/confidential-containers/attestation-service/tdx"
FILE_NAME = "platform_collaterals.json"
COLLATERAL_SERVICE = f"file://{MOUNT_DIR}/{FILE_NAME}"


def fetch() -> bytes:
    """Download the collateral for all server platforms with Intel's pcsclient."""
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / FILE_NAME
        try:
            result = subprocess.run(
                ["pcsclient", "fetch", "-p", "E5", "-t", "all", "-o", str(out)],
                stdin=subprocess.DEVNULL, capture_output=True, text=True)
        except FileNotFoundError:
            raise RuntimeError("pcsclient not found: run veritas from the coco-tools "
                               "image or install Intel's PCS client tool")
        if result.returncode != 0 or not out.exists():
            raise RuntimeError(f"pcsclient fetch failed: {result.stdout}{result.stderr}".strip())
        return out.read_bytes()


def next_update(data: bytes) -> datetime:
    """Earliest nextUpdate of the TDX TCB info and TD QE identity."""
    try:
        col = json.loads(data)["collaterals"]
        dates = [e[k]["tcbInfo"]["nextUpdate"]
                 for e in col["tcbinfos"] for k in ("tdx_tcbinfo", "tdx_tcbinfo_early") if k in e]
        dates += [col[k]["enclaveIdentity"]["nextUpdate"]
                  for k in ("tdqeidentity", "tdqeidentity_early") if col.get(k)]
    except (ValueError, KeyError, TypeError) as e:
        raise RuntimeError(f"Invalid TDX collateral: {e}")
    if not dates:
        raise RuntimeError("Invalid TDX collateral: no TDX TCB info")
    return min(datetime.fromisoformat(d) for d in dates)


def check(secrets: dict, mounts: dict) -> tuple[bool, str]:
    """Check the manifests carry valid TDX collateral. Returns (ok, message)."""
    if FILE_NAME not in secrets.get(SECRET_NAME, {}):
        return False, f"missing Secret {SECRET_NAME}"
    if mounts.get(SECRET_NAME) != MOUNT_DIR:
        return False, f"{SECRET_NAME} not mounted at {MOUNT_DIR}"
    try:
        expires = next_update(secrets[SECRET_NAME][FILE_NAME])
    except RuntimeError as e:
        return False, str(e)
    if expires < datetime.now(timezone.utc):
        return False, f"collateral expired on {expires:%Y-%m-%d}, re-run render"
    return True, f"collateral expires {expires:%Y-%m-%d}"


def render() -> tuple[dict, list[dict]]:
    """Returns ({secret name: {file name: bytes}}, cert cache entries for KbsConfig)."""
    data = fetch()
    next_update(data)
    return ({SECRET_NAME: {FILE_NAME: data}},
            [{"secretName": SECRET_NAME, "mountPath": MOUNT_DIR}])
