#!/usr/bin/env python3
"""Run veritas for every platform/tee/version in a support matrix.

For baremetal: discovers OCP z-stream versions from the OCP release repo,
filtered by min_z entries in the support matrix.

For azure: discovers OSC operator z-stream versions from the dm-verity
image repo, derived from the osc_version in the support matrix.

Usage:
    ./scripts/compute-all.py --support-matrix osc-support-1.11.json --dry-run
    ./scripts/compute-all.py --support-matrix osc-support-1.11.json --authfile pull-secret.json
"""

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path


OCP_RELEASE_REPO = "quay.io/openshift-release-dev/ocp-release"
DM_VERITY_REPO = "registry.redhat.io/openshift-sandboxed-containers/osc-dm-verity-image"
TEES = ["tdx", "snp"]


def parse_version(v):
    return tuple(int(x) for x in v.split("."))


def fetch_tags(repo):
    """Query registry for all available tags."""
    result = subprocess.run(
        ["skopeo", "list-tags", f"docker://{repo}"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"skopeo list-tags failed for {repo}:\n{result.stderr}")
    return json.loads(result.stdout)["Tags"]


def discover_ocp_versions(all_tags, min_version):
    """Filter OCP tags to versions >= min_version within the same minor."""
    min_parts = parse_version(min_version)
    minor_prefix = f"{min_parts[0]}.{min_parts[1]}."

    versions = []
    for tag in all_tags:
        if not tag.endswith("-x86_64"):
            continue
        v = tag.removesuffix("-x86_64")
        if not v.startswith(minor_prefix):
            continue
        if not re.match(r"^4\.\d+\.\d+$", v):
            continue
        if parse_version(v) >= min_parts:
            versions.append(v)

    versions.sort(key=parse_version)
    return versions


def discover_osc_versions(all_tags, osc_major_minor):
    """Filter dm-verity image tags to clean versions matching the major.minor."""
    prefix = f"{osc_major_minor}."
    versions = []
    for tag in all_tags:
        if not tag.startswith(prefix):
            continue
        if not re.match(r"^\d+\.\d+\.\d+$", tag):
            continue
        versions.append(tag)

    versions.sort(key=parse_version)
    return versions


def run_veritas(platform, tee, authfile, output_dir, ocp_versions=None, osc_versions=None):
    """Run veritas with all versions at once, producing merged output."""
    cmd = [
        sys.executable, "-m", "veritas",
        "--platform", platform,
        "--tee", tee,
        "--authfile", str(authfile),
        "-o", str(output_dir),
    ]
    for v in (ocp_versions or []):
        cmd.extend(["--ocp-version", v])
    for v in (osc_versions or []):
        cmd.extend(["--osc-version", v])

    log_path = output_dir / "veritas.log"
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    assert proc.stdout is not None
    with open(log_path, "w") as log_file:
        for line in proc.stdout:
            sys.stderr.write(line)
            log_file.write(line)
    proc.wait()
    return proc.returncode == 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--support-matrix", required=True, help="Support matrix JSON")
    parser.add_argument("--authfile", help="Registry auth file")
    parser.add_argument("--platform", choices=["baremetal", "azure"], help="Run only this platform")
    parser.add_argument("--dry-run", action="store_true", help="List versions without running veritas")
    parser.add_argument("-o", "--output", help="Output directory (default: tmpdir)")
    args = parser.parse_args()

    if not args.dry_run and not args.authfile:
        parser.error("--authfile is required unless --dry-run is used")

    with open(args.support_matrix) as f:
        matrix = json.load(f)

    osc_major_minor = matrix["osc_version"]
    platforms = matrix["platforms"]
    if args.platform:
        platforms = {args.platform: platforms[args.platform]}

    # Build plan per platform
    plan = {}

    if "baremetal" in platforms:
        print("Querying OCP release repo...")
        ocp_tags = fetch_tags(OCP_RELEASE_REPO)
        bm_versions = []
        for min_z in platforms["baremetal"]["min_z"]:
            bm_versions.extend(discover_ocp_versions(ocp_tags, min_z))
        plan["baremetal"] = {"type": "ocp", "versions": bm_versions}

    if "azure" in platforms:
        print("Querying dm-verity image repo...")
        dm_tags = fetch_tags(DM_VERITY_REPO)
        osc_versions = discover_osc_versions(dm_tags, osc_major_minor)
        plan["azure"] = {"type": "osc", "versions": osc_versions}

    for platform, info in plan.items():
        label = "OCP" if info["type"] == "ocp" else "OSC"
        print(f"\n{platform}: {len(info['versions'])} {label} versions")
        for v in info["versions"]:
            print(f"  {v}")

    print(f"\nTotal runs: {len(plan) * len(TEES)}")

    if args.dry_run:
        return

    outdir = Path(args.output) if args.output else Path(tempfile.mkdtemp(prefix="veritas-compute-all-"))
    outdir.mkdir(parents=True, exist_ok=True)
    print(f"\nOutput directory: {outdir}")

    for platform, info in plan.items():
        for tee in TEES:
            label = f"{platform}/{tee}"
            tee_dir = outdir / platform / tee
            tee_dir.mkdir(parents=True, exist_ok=True)

            versions_str = ", ".join(info["versions"])
            print(f"  {label} ({versions_str}) ... ", end="", flush=True)
            kwargs = {"platform": platform, "tee": tee, "authfile": args.authfile, "output_dir": tee_dir}
            if info["type"] == "ocp":
                kwargs["ocp_versions"] = info["versions"]
            else:
                kwargs["osc_versions"] = info["versions"]
            if run_veritas(**kwargs):
                print("OK")
            else:
                print(f"FAILED (see {tee_dir}/veritas.log)")

    print(f"\nDone. Results in: {outdir}")


if __name__ == "__main__":
    main()
