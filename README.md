# veritas

> Not the woodworking kind. This one computes attestation truth.

Extracts attestation reference values for OpenShift Sandboxed
Containers from the actual cluster artifacts.

Point it at your OCP cluster, get the values Trustee needs.

> [!WARNING]
> For baremetal, veritas uses `oc adm release info` to resolve the
> extensions image from the cluster's OCP release. If the cluster is
> compromised, the resolved artifacts could be tampered with. Make
> sure you trust the cluster before using these values for attestation.
> For Azure, artifacts are pulled directly from the Red Hat registry
> and signature verified via cosign.

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

# Output as Trustee RVPS ConfigMap YAML
veritas --platform baremetal --tee tdx -f trustee

# Save to file
veritas --platform baremetal --tee tdx -f trustee -o rvps-configmap.yaml
```

Output goes to stdout by default. Use `-o` to write to a file.

## What it computes

| <div style="width:300px">Component</div> | Azure (SHA-256) | Baremetal TDX (SHA-384) | Baremetal SNP (SHA-384) |
|---|---|---|---|
| 🟢 💾 Firmware (OVMF) | pcr03 | mr_td | *combined in `measurement`* |
| 🟢 💾 Kernel ¹ | | tdvfkernel | *combined in `measurement`* |
| 🟢 💾 Kernel cmdline ² | | tdvfkernelparams | *combined in `measurement`* |
| 🟢 💾 Initrd | pcr09 | initrd | *combined in `measurement`* |
| 🔴 💾 Runtime registers | | rtmr_0, rtmr_1, rtmr_2 | |
| 🟢 💾 UKI bundle | pcr11 | | |
| 🟢 💾 Credentials | pcr12 | | |
| 🟢 💾 Launch digest | | | measurement |
| 🟢 ⚙️ Init data | pcr08 | init_data (mr_config_id) | init_data |
| 🔴 🔒 TEE type | | tee_type | |
| 🔴 🔒 Vendor ID | | vendor_id | |
| 🔴 🔒 TEE firmware | | mr_seam | |
| 🔴 🔒 TCB version | | tcb_svn | reported_tcb_* |
| 🔴 🔒 TCB status | | tcb_status | |
| 🔴 🔒 Collateral expiry | | collateral_expiration_status | |
| 🔴 🔒 CPU features | | xfam | |
| 🔴 🔒 Debug policy | | td_attributes | policy_debug_allowed |
| 🔴 🔒 SMT policy | | | platform_smt_enabled |

🟢 supported by veritas · 🔴 not yet supported

💾 software: pre-computable from cluster artifacts
⚙️ user config: computed from user-provided input (e.g. initdata.toml)
🔒 hardware: can't be pre-computed, must come from a live TD quote

<small><i>¹ QEMU patches the kernel setup header (memory addresses, initrd location) before OVMF measures it. The hash depends on the VM memory layout, which may vary with different kata configurations. This is a known QEMU bug, already fixed upstream but not yet in RHEL. Once RHEL picks up the fix, a plain PE hash of vmlinuz will match.</i></small>

<small><i>² The kernel command line includes nr_cpus=N which kata sets based on the pod's CPU resource request. A pod requesting 4 CPUs will have a different hash than one requesting 1. Veritas currently hardcodes nr_cpus=1. This is unrelated to the QEMU bug and will remain an issue until the cmdline is discovered dynamically or multiple reference values are supported for different CPU counts.</i></small>

## Output examples

### JSON (default)

```json
{
  "platform": "baremetal",
  "evidence_type": "tdx",
  "executables": [
    {
      "name": "tdvfkernel",
      "value": "5cc7bd73ff2ae5b75b9011cd1f0616dc45cddc31b4b0bbc6...",
      "description": "Kernel binary (vmlinuz) digest from UEFI event log",
      "algorithm": "sha384",
      "source": "kata-containers RPM (PE image region hash, unpatched)"
    },
    {
      "name": "tdvfkernelparams",
      "value": "2314211f527fb49d1e548228084c444dfe1c5221bd2f411f...",
      "description": "Kernel command line (UTF-16-LE) digest from UEFI event log",
      "algorithm": "sha384",
      "source": "hardcoded default kata kernel cmdline"
    },
    {
      "name": "initrd",
      "value": "3ec83629255e3071cf5a9ae5a26e6174deddf4dcdb164cac...",
      "description": "Initrd (kata-cc.initrd) digest from UEFI event log",
      "algorithm": "sha384",
      "source": "kata-containers RPM (sha384 of file)"
    },
    {
      "name": "mr_td",
      "value": "27fb849fb05653add8be4b8c5b2793e66d1e25773a5c6f80...",
      "description": "TD build-time measurement (OVMF/TDVF)",
      "algorithm": "sha384",
      "source": "TDVF descriptor from OVMF.inteltdx.fd"
    }
  ],
  "hardware": [],
  "configuration": []
}
```

### Trustee RVPS ConfigMap (`-f trustee`)

```yaml
# Generated by veritas (platform: baremetal)
apiVersion: v1
kind: ConfigMap
metadata:
  name: rvps-reference-values
  namespace: trustee-operator-system
data:
  reference-values: |
    [
      {
        "name": "tdvfkernel",
        "expiration": "2099-12-31T00:00:00Z",
        "value": [
          "5cc7bd73ff2ae5b75b9011cd1f0616dc45cddc31b4b0bbc6..."
        ]
      },
      {
        "name": "tdvfkernelparams",
        "expiration": "2099-12-31T00:00:00Z",
        "value": [
          "2314211f527fb49d1e548228084c444dfe1c5221bd2f411f..."
        ]
      },
      {
        "name": "initrd",
        "expiration": "2099-12-31T00:00:00Z",
        "value": [
          "3ec83629255e3071cf5a9ae5a26e6174deddf4dcdb164cac..."
        ]
      },
      {
        "name": "mr_td",
        "expiration": "2099-12-31T00:00:00Z",
        "value": [
          "27fb849fb05653add8be4b8c5b2793e66d1e25773a5c6f80..."
        ]
      }
    ]
```

Apply directly with `oc apply -f rvps-configmap.yaml`.

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
- [ ] Integrate tdx-measure for RTMR computation (rtmr_0, rtmr_1, rtmr_2)
- [ ] Collect hardware values (mr_seam, tcb_svn, xfam) from a running TD
- [ ] Discover kernel command line from kata configuration instead of hardcoding
- [ ] CGPU (Confidential GPU) support

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE)
for details.
