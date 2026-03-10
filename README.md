# veritas

> I like Veritas tools, but this one is about truth, not woodworking.

Extracts attestation reference values for OpenShift Sandboxed
Containers from the actual cluster artifacts.

Point it at your OCP cluster, get the values Trustee needs.

## Why

Trustee needs RVPS reference values to verify confidential workloads.
These values come from the exact firmware, kernel, and initrd that the
cluster runs. Veritas pulls those artifacts directly from the OCP
release (pinned by digest), computes the hashes, and outputs them
ready for Trustee.

## Supported platforms

| Platform | TEE | Artifact source |
|---|---|---|
| Azure (peer-pods) | TDX, SNP | osc-dm-verity-image (pre-computed PCRs) |
| Baremetal | TDX, SNP | kata-containers and edk2-ovmf RPMs from rhel-coreos-extensions |

## Prerequisites

- `oc`: resolves the rhel-coreos-extensions image reference from the OCP release
- `podman`: pulls container images and extracts RPMs and artifacts
- `skopeo`: queries the registry for image digests
- `cosign`: verifies Red Hat image signatures (Azure only)
- `KUBECONFIG` environment variable pointing to the target cluster

## Install

```
# Base install (Azure, Baremetal TDX)
pip install .

# With SNP support (adds sev-snp-measure)
pip install .[snp]
```

## Usage

```
export KUBECONFIG=/path/to/kubeconfig

# Azure peer-pods
veritas --platform azure --tee tdx --authfile pull-secret.json

# Baremetal TDX
veritas --platform baremetal --tee tdx

# Include initdata hash
veritas --platform baremetal --tee tdx --initdata initdata.toml

# Verbose output
veritas --platform baremetal --tee tdx -v
```

Output is written to `output.json` by default (override with `-o`).

## What it computes

| Component | Azure (SHA-256) | Baremetal TDX (SHA-384) | Baremetal SNP (SHA-384) |
|---|---|---|---|
| **Software** | | | |
| Firmware (OVMF) | pcr03 | mr_td | *combined in `measurement`* |
| Kernel | | tdvfkernel | *combined in `measurement`* |
| Kernel cmdline | | tdvfkernelparams | *combined in `measurement`* |
| Initrd | pcr09 | initrd | *combined in `measurement`* |
| UKI bundle | pcr11 | | |
| Credentials | pcr12 | | |
| Init data | pcr08 | | |
| Launch digest | | | measurement |
| **Hardware** | | | |
| TEE firmware | | mr_seam | |
| TCB version | | tcb_svn | reported_tcb_* |
| CPU features | | xfam | |
| Debug policy | | td_attributes | policy_debug_allowed |
| SMT policy | | | platform_smt_enabled |

Software values are pre-computable from the cluster artifacts.
Hardware values must be captured from a running TD or SNP guest.
Veritas does not collect hardware values yet.

## Known limitations

**tdvfkernel uses vendored patching logic.** RHEL's QEMU 9.1.0
patches the kernel setup header before OVMF measures it, so the
hash of the original vmlinuz does not match the UEFI event log.
To produce the correct hash, veritas vendors a Python port of
QEMU's patching logic (based on
[virtee/tdx-measure](https://github.com/virtee/tdx-measure)).
Once RHEL ships a newer QEMU that skips patching for TDX guests
(already fixed upstream), this vendored code can be removed and
a plain hash of vmlinuz will suffice.

**Hardware values are not collected.** Values like mr_seam, tcb_svn,
and xfam come from the TDX hardware or AMD platform and cannot be
pre-computed. They must be captured from a running TD or SNP guest
and added to the RVPS manually.

**Kernel command line is hardcoded.** The kata kernel command line is
assembled at runtime from multiple source files in the kata-containers
repository. Veritas uses the known default value. If your deployment
customizes the kernel command line, the tdvfkernelparams hash will
not match.

## TODO

- [ ] Remove vendored QEMU patching logic once RHEL ships a fixed QEMU
- [ ] Collect hardware values (mr_seam, tcb_svn, xfam) from a running TD
- [ ] Discover kernel command line from kata configuration instead of hardcoding
- [ ] Trustee-ready output format (RVPS ConfigMap YAML)

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE)
for details.
