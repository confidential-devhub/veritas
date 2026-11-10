"""AMD SEV-SNP collateral (VCEK certificates)."""

import re
import subprocess
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

KDS_HOST = "kdsintf.amd.com"
PRODUCTS = {"Milan", "Genoa", "Turin"}
TCB_FIELDS = ("blSPL", "teeSPL", "snpSPL", "ucodeSPL", "fmcSPL")
VCEK_MOUNT_DIR = "/opt/confidential-containers/attestation-service/kds-store/vcek"


def parse_vcek_url(url: str) -> dict:
    """Parse and validate `snphost show vcek-url` output.

    The URL comes from the node, so it is untrusted input.
    """
    u = urlparse(url.strip())
    if u.scheme != "https" or u.hostname != KDS_HOST:
        raise ValueError(f"Unexpected VCEK URL host: {url}")

    m = re.fullmatch(r"/vcek/v1/(\w+)/([0-9a-fA-F]+)", u.path)
    if not m or m.group(1) not in PRODUCTS:
        raise ValueError(f"Unexpected VCEK URL path: {u.path}")
    product, hwid = m.group(1), m.group(2).lower()  # Trustee looks up lowercase
    if len(hwid) != (16 if product == "Turin" else 128):
        raise ValueError(f"Unexpected hwid length for {product}: {len(hwid)}")

    tcb = {}
    for key, vals in parse_qs(u.query, strict_parsing=True).items():
        if key not in TCB_FIELDS or len(vals) != 1 or not vals[0].isdigit():
            raise ValueError(f"Unexpected VCEK URL parameter: {key}")
        spl = int(vals[0])
        if spl > 255:
            raise ValueError(f"{key} out of range: {spl}")
        tcb[key] = spl

    return {"product": product, "hwid": hwid, "tcb": tcb}


def vcek_url(node: dict) -> str:
    """Build the KDS URL for a request entry, validating it on the way."""
    try:
        url = (f"https://{KDS_HOST}/vcek/v1/{node['product']}/{node['hwid']}?"
               + urlencode(node["tcb"]))
    except (KeyError, TypeError) as e:
        raise ValueError(f"{node.get('name')}: malformed SNP entry: {e}")
    parse_vcek_url(url)
    return url


def fetch(url: str) -> bytes:
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            return r.read()
    except OSError as e:
        raise RuntimeError(f"Failed to download {url}: {e}")


def cert_chain_url(product: str) -> str:
    return f"https://{KDS_HOST}/vcek/v1/{product}/cert_chain"


def split_cert_chain(pem: bytes) -> dict:
    """Split the KDS cert_chain (ASK then ARK) into snpguest file names."""
    end = b"-----END CERTIFICATE-----\n"
    certs = [c.strip() + b"\n" + end for c in pem.split(end.strip()) if c.strip()]
    if len(certs) != 2:
        raise RuntimeError(f"Expected ASK and ARK in cert_chain, got {len(certs)} certificates")
    return {"ask.pem": certs[0], "ark.pem": certs[1]}


def verify_certs(ark: bytes, ask: bytes, vcek: bytes):
    """Check the VCEK chains up to the ARK with `snpguest verify certs`."""
    with tempfile.TemporaryDirectory() as tmp:
        for name, data in (("ark.pem", ark), ("ask.pem", ask), ("vcek.der", vcek)):
            (Path(tmp) / name).write_bytes(data)
        try:
            result = subprocess.run(["snpguest", "verify", "certs", tmp],
                                    capture_output=True, text=True)
        except FileNotFoundError:
            raise RuntimeError("snpguest not found: run veritas from the coco-tools "
                               "image or install snpguest")
    if result.returncode != 0:
        raise RuntimeError(f"VCEK chain verification failed: {result.stderr.strip()}")


def not_after(der: bytes) -> datetime:
    from cryptography import x509
    try:
        return x509.load_der_x509_certificate(der).not_valid_after_utc
    except ValueError as e:
        raise RuntimeError(f"Invalid VCEK certificate: {e}")


def vcek_file(tcb: dict) -> str:
    """File name Trustee looks up for a given TCB (OfflineStore)."""
    name = "bl{blSPL:02}_tee{teeSPL:02}_snp{snpSPL:02}_ucode{ucodeSPL:02}".format(**tcb)
    if "fmcSPL" in tcb:
        name += f"_fmc{tcb['fmcSPL']:02}"
    return name + "_vcek.der"


def check(node: dict, secrets: dict, mounts: dict) -> tuple[bool, str]:
    """Check the manifests cover a node. Returns (ok, message)."""
    name = secret_name(node["hwid"])
    if name not in secrets:
        return False, f"missing Secret {name}"
    if mounts.get(name) != f"{VCEK_MOUNT_DIR}/{node['hwid']}":
        return False, f"{name} not mounted at {VCEK_MOUNT_DIR}/{node['hwid']}"
    files = secrets[name]
    vcek = vcek_file(node["tcb"])
    if vcek not in files:
        return False, f"{name} has no {vcek}, firmware changed? re-run render"
    try:
        expires = not_after(files[vcek])
        if expires < datetime.now(timezone.utc):
            return False, f"VCEK expired on {expires:%Y-%m-%d}, re-run render"
        verify_certs(files.get("ark.pem", b""), files.get("ask.pem", b""), files[vcek])
    except RuntimeError as e:
        return False, str(e)
    return True, f"VCEK expires {expires:%Y-%m-%d}"


def secret_name(hwid: str) -> str:
    # The operator uses the Secret name as volume name (max 63 chars).
    return f"vcek-{hwid[:16]}"


def render(nodes: list[dict]) -> tuple[dict, list[dict]]:
    """Download and verify one VCEK per chip, plus the AMD cert chain.

    Returns ({secret name: {file name: bytes}}, cert cache entries for KbsConfig).
    """
    chains, files = {}, {}
    for node in nodes:
        url = vcek_url(node)
        if node["hwid"] in files:
            continue
        product = node["product"]
        if product not in chains:
            chains[product] = split_cert_chain(fetch(cert_chain_url(product)))
        vcek = fetch(url)
        verify_certs(chains[product]["ark.pem"], chains[product]["ask.pem"], vcek)
        files[node["hwid"]] = {**chains[product], vcek_file(node["tcb"]): vcek}

    entries = [{"secretName": secret_name(h), "mountPath": f"{VCEK_MOUNT_DIR}/{h}"}
               for h in files]
    return {secret_name(h): f for h, f in files.items()}, entries
