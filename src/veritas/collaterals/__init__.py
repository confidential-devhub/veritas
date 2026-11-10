"""Attestation collateral for disconnected clusters."""

import argparse
import base64
import io
import json
import logging
import shlex
import subprocess
import sys
import tarfile
from pathlib import Path

from veritas.collaterals import snp, tdx
from veritas.models import RVPS_NAMESPACE

log = logging.getLogger(__name__)

COCO_TOOLS_IMAGE = "quay.io/openshift_sandboxed_containers/coco-tools:0.5.1"
REQUEST_VERSION = 1

# Runs inside `oc debug node/...`, host filesystem mounted at /host.
PROBE = """\
if grep -qs Y /host/sys/module/kvm_amd/parameters/sev_snp; then
  echo tee=snp
  chroot /host podman run --rm --privileged {image} /tools/snphost show vcek-url
elif grep -qs Y /host/sys/module/kvm_intel/parameters/tdx; then
  echo tee=tdx
else
  echo tee=none
fi
"""


def oc(*args) -> str:
    result = subprocess.run(["oc", *args], capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"oc {' '.join(args)}\n{result.stderr}")
    return result.stdout


def list_nodes(selector: str) -> list[str]:
    out = oc("get", "nodes", "-l", selector, "-o", "name")
    return [line.removeprefix("node/") for line in out.split()]


def probe_node(node: str, image: str) -> dict | None:
    """Detect the node TEE and collect what it needs. None if no TEE."""
    out = oc("debug", f"node/{node}", "--", "sh", "-c",
             PROBE.format(image=shlex.quote(image)))
    lines = out.strip().splitlines()
    tee = next((l.removeprefix("tee=") for l in lines if l.startswith("tee=")), None)

    if tee == "snp":
        url = next((l for l in lines if l.startswith("https://")), None)
        if url is None:
            raise RuntimeError(f"{node}: snphost did not return a VCEK URL")
        return {"name": node, "tee": "snp", **snp.parse_vcek_url(url)}
    if tee == "tdx":
        return {"name": node, "tee": "tdx"}
    return None


def confirm(nodes: list[str], image: str) -> bool:
    server = oc("whoami", "--show-server").strip()
    print(f"""\
About to connect to cluster {server} and, on each node below, start a
privileged debug pod (oc debug) that runs {image}
to read the TEE identifiers. Nothing is changed on the cluster.

Nodes: {", ".join(nodes)}
""", file=sys.stderr)
    if not sys.stdin.isatty():
        raise RuntimeError("Not running interactively, pass --yes to continue")
    return input("Continue? [y/N] ").strip().lower() in ("y", "yes")


def is_azure(node: str) -> bool:
    return oc("get", "node", node, "-o", "jsonpath={.spec.providerID}").startswith("azure://")


def collect(nodes: list[str], image: str) -> dict:
    entries = []
    for node in nodes:
        if is_azure(node):
            log.info("%s: Azure node, recorded as TDX (SNP needs no collateral on Azure)", node)
            entries.append({"name": node, "tee": "tdx"})
            continue
        log.info("Probing node %s", node)
        entry = probe_node(node, image)
        if entry is None:
            log.warning("%s: no SNP or TDX support detected, skipping", node)
            continue
        log.info("%s: %s", node, entry["tee"])
        entries.append(entry)
    return {"version": REQUEST_VERSION, "nodes": entries}


def load_request(path: str) -> list[dict]:
    request = json.loads(Path(path).read_text())
    if request.get("version") != REQUEST_VERSION:
        raise ValueError(f"Unsupported request version: {request.get('version')}")
    return request["nodes"]


def merge_cert_cache(kbsconfig: dict | None, new: list[dict]) -> list[dict]:
    """Return the full kbsLocalCertCacheSpec.secrets list.

    A merge patch replaces lists, so existing entries must be kept here.
    """
    spec = (kbsconfig or {}).get("spec", {})
    merged = list(spec.get("kbsLocalCertCacheSpec", {}).get("secrets", []))
    names = {e["secretName"]: i for i, e in enumerate(merged)}
    for entry in new:
        i = names.get(entry["secretName"])
        if i is None:
            merged.append(entry)
        elif merged[i] != entry:
            log.warning("Replacing existing entry for %s", entry["secretName"])
            merged[i] = entry
        else:
            log.info("%s already in KbsConfig", entry["secretName"])
    return merged


def format_secrets(files: dict, namespace: str) -> str:
    docs = []
    for name, data in files.items():
        docs.append(
            f"apiVersion: v1\n"
            f"kind: Secret\n"
            f"metadata:\n"
            f"  name: {name}\n"
            f"  namespace: {namespace}\n"
            f"type: Opaque\n"
            f"data:\n"
            + "".join(f"  {k}: {base64.b64encode(v).decode()}\n" for k, v in data.items()))
    return "---\n".join(docs)


def format_patch(entries: list[dict]) -> str:
    lines = ["spec:", "  kbsLocalCertCacheSpec:", "    secrets:"]
    for e in entries:
        lines.append(f"    - secretName: {e['secretName']}")
        lines.append(f"      mountPath: {e['mountPath']}")
    return "\n".join(lines) + "\n"


def write_bundle(path: str, files: dict):
    with tarfile.open(path, "w") as tar:
        for secret, data in files.items():
            for name, content in data.items():
                info = tarfile.TarInfo(f"{secret}/{name}")
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))


def read_manifests(out: Path) -> tuple[dict, dict]:
    """Read back the files written by render.

    Returns ({secret name: {file name: bytes}}, {secret name: mount path}).
    """
    secrets, name, in_data = {}, None, False
    for line in (out / "secrets.yaml").read_text().splitlines():
        key, _, value = line.strip().partition(": ")
        if key == "name":
            name, in_data = value, False
            secrets[name] = {}
        elif line == "data:":
            in_data = True
        elif in_data and line.startswith("  "):
            secrets[name][key] = base64.b64decode(value)

    mounts, name = {}, None
    for line in (out / "kbsconfig.patch").read_text().splitlines():
        key, _, value = line.strip().removeprefix("- ").partition(": ")
        if key == "secretName":
            name = value
        elif key == "mountPath":
            mounts[name] = value
    return secrets, mounts


def verify(request: str, manifests: str) -> bool:
    nodes = load_request(request)
    secrets, mounts = read_manifests(Path(manifests))
    ok = True
    for node in nodes:
        if node.get("tee") == "snp":
            node_ok, msg = snp.check(node, secrets, mounts)
        else:
            node_ok, msg = tdx.check(secrets, mounts)
        ok &= node_ok
        print(f"{node.get('name')}\t{node.get('tee')}\t{'ok' if node_ok else 'FAIL'}\t{msg}")
    return ok


def render(args):
    nodes = load_request(args.request)
    snp_nodes = [n for n in nodes if n.get("tee") == "snp"]
    has_tdx = any(n.get("tee") == "tdx" for n in nodes)
    if not snp_nodes and not has_tdx:
        raise RuntimeError(f"No SNP or TDX nodes in {args.request}")

    kbsconfig = json.loads(Path(args.kbsconfig).read_text()) if args.kbsconfig else None

    files, entries = {}, []
    if snp_nodes:
        snp_files, snp_entries = snp.render(snp_nodes)
        files |= snp_files
        entries += snp_entries
        log.info("Downloaded and verified %d VCEK(s)", len(snp_files))
    if has_tdx:
        tdx_files, tdx_entries = tdx.render()
        files |= tdx_files
        entries += tdx_entries
        log.info("Downloaded TDX collateral")

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    (out / "secrets.yaml").write_text(format_secrets(files, args.namespace))
    (out / "kbsconfig.patch").write_text(format_patch(merge_cert_cache(kbsconfig, entries)))
    if args.bundle:
        write_bundle(args.bundle, files)
        log.info("Written %s", args.bundle)

    if not kbsconfig:
        log.warning("No --kbsconfig given: the patch replaces any existing "
                    "kbsLocalCertCacheSpec entries")
    name = kbsconfig["metadata"]["name"] if kbsconfig else "<kbsconfig>"
    log.info("Written %s. On the Trustee cluster run:\n"
             "  oc apply --server-side -f %s\n"
             "  oc patch kbsconfig %s -n %s --type merge --patch-file %s",
             out, out / "secrets.yaml", name, args.namespace, out / "kbsconfig.patch")
    if has_tdx:
        configmap = (kbsconfig or {}).get("spec", {}).get("kbsConfigMapName", "<kbs-config>")
        log.warning("TDX: once, set in ConfigMap %s, under "
                    "[attestation_service.verifier_config.dcap_verifier]:\n"
                    "  collateral_service = \"%s\"\n"
                    "and restart Trustee.", configmap, tdx.COLLATERAL_SERVICE)

    if args.verify and not verify(args.request, out):
        raise RuntimeError("Verification failed")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="veritas collateral", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("collect", help="Read TEE identifiers from cluster nodes (read-only)")
    nodes = p.add_mutually_exclusive_group(required=True)
    nodes.add_argument("--node", action="append", dest="nodes", help="Node name (repeatable)")
    nodes.add_argument("--selector", help="Node label selector, e.g. node-role.kubernetes.io/worker=")
    p.add_argument("--image", default=COCO_TOOLS_IMAGE, help=f"coco-tools image (default: {COCO_TOOLS_IMAGE})")
    p.add_argument("-y", "--yes", action="store_true", help="Do not ask for confirmation")
    p.add_argument("-o", "--output", default="request.json", help="Output file (default: request.json)")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    p = sub.add_parser("render", help="Download collateral and write Trustee manifests (needs internet)")
    p.add_argument("request", help="request.json from collect")
    p.add_argument("--kbsconfig", help="Current KbsConfig as JSON (oc get kbsconfig NAME -o json), "
                   "so existing cert cache entries are kept")
    p.add_argument("--namespace", default=RVPS_NAMESPACE, help=f"Trustee namespace (default: {RVPS_NAMESPACE})")
    p.add_argument("-o", "--output", default="manifests", help="Output directory (default: manifests)")
    p.add_argument("-b", "--bundle", help="Also write the downloaded files to this tar, for debugging")
    p.add_argument("--verify", action="store_true", help="Run verify on the output")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    p = sub.add_parser("verify", help="Check the manifests cover every node in the request (offline)")
    p.add_argument("request", help="request.json from collect")
    p.add_argument("manifests", help="Directory written by render")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    if args.command in ("render", "verify"):
        try:
            if args.command == "render":
                render(args)
            elif not verify(args.request, args.manifests):
                sys.exit(1)
        except (RuntimeError, ValueError, OSError) as e:
            log.error("%s", e)
            sys.exit(1)
        return

    try:
        names = args.nodes or list_nodes(args.selector)
        if not names:
            raise RuntimeError(f"No nodes match selector {args.selector}")
        if not args.yes and not confirm(names, args.image):
            log.info("Aborted")
            sys.exit(1)
        request = collect(names, args.image)
    except (RuntimeError, ValueError) as e:
        log.error("%s", e)
        sys.exit(1)

    Path(args.output).write_text(json.dumps(request, indent=2) + "\n")
    log.info("Written %s (%d nodes)", args.output, len(request["nodes"]))
