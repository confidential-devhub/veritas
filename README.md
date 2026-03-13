# veritas

> Not the woodworking kind. This one computes attestation truth.

Extracts attestation reference values for OpenShift Sandboxed
Containers from OCP release artifacts and Red Hat registry images.

Point it at an OCP version, get the values Trustee needs.

For baremetal, veritas resolves the extensions image from the OCP
release payload and verifies its signature with `oc adm release info
--verify`. For Azure, artifacts are pulled from the Red Hat registry
and signature verified via cosign. No cluster access is required.

## Why

Trustee needs RVPS reference values to verify confidential workloads.
These values come from the exact firmware, kernel, and initrd shipped
in each OCP release. Veritas pulls those artifacts directly from the
release payload (pinned by digest), computes the hashes, and outputs
them ready for Trustee.

## Supported platforms

| Platform | TEE | Artifact source |
|---|---|---|
| Azure | TDX, SNP | osc-dm-verity-image (pre-computed PCRs) |
| Baremetal | TDX, SNP | kata-containers and edk2-ovmf RPMs from rhel-coreos-extensions |

## Prerequisites

- `oc`: resolves and extracts the rhel-coreos-extensions image from the OCP release
- `skopeo`: queries the registry for image digests
- `cosign`: verifies Red Hat image signatures (Azure only)
- `tdx-measure`: computes TDX runtime measurement registers (Baremetal TDX only, `cargo install --git https://github.com/virtee/tdx-measure tdx-measure-cli`)

## Install

```
# Base install (Azure, Baremetal TDX)
pip install .

# With SNP support (adds sev-snp-measure)
pip install .[snp]
```

## Usage

```
# Baremetal TDX
veritas --platform baremetal --tee tdx --ocp-version 4.20.15 \
  --authfile pull-secret.json \
  --initdata initdata.toml

# Azure TDX
veritas --platform azure --tee tdx \
  --authfile pull-secret.json \
  --initdata initdata.toml
```

Output is written to the current directory by default.
Use `-o` to specify a different directory.

> [!NOTE]
> The defaults match standard kata configurations and OCP artifacts.
> If your environment uses different settings (VM memory size, kernel
> command line, CPU features), see the platform docs for additional
> flags that ensure the RVPS values match your setup.
> See [Baremetal](BAREMETAL.md) and [Azure](AZURE.md) for
> platform-specific options and examples.

## Computing all supported versions

Different z-stream releases may ship different artifacts, producing
different hashes. To cover all supported versions in a single RVPS
ConfigMap, veritas merges them into one value list per key:

```json
{
  "name": "tdx_pcr09",
  "value": [
    "f831563c60f456009066a9fe...",
    "23ab4e921bc667fbb6703e9f..."
  ]
}
```

The attestation policy uses set membership (`in`), so any of the
listed values will pass verification.

`compute-all.py` automates this across all supported z-stream
versions. It reads a support matrix JSON that defines the minimum
supported version per platform, queries the registries to discover
every z-stream from that minimum onward, and runs veritas once per
platform/tee with all versions merged.

```
# See which versions would be processed
python3 scripts/compute-all.py --support-matrix osc-support-1.11.json --dry-run

# Run all platforms
python3 scripts/compute-all.py --support-matrix osc-support-1.11.json --authfile pull-secret.json

# Run a single platform
python3 scripts/compute-all.py --support-matrix osc-support-1.11.json --platform azure --authfile pull-secret.json

# Save output to a specific directory
python3 scripts/compute-all.py --support-matrix osc-support-1.11.json --authfile pull-secret.json -o results/
```

The support matrix maps platforms to their minimum z-stream versions.
For baremetal, these are OCP versions. For azure, these are OSC
operator versions (the dm-verity image is tied to the operator
release, not OCP). See `osc-support-*.json` for the current matrix.

## Default policy coverage

Maps each value checked by the [upstream default Rego policy](https://github.com/confidential-containers/trustee/blob/main/attestation-service/src/token/ear_default_policy_cpu.rego) to what veritas can provide today. Each cell shows the RVPS key name and whether veritas computes it, the policy hardcodes it, or it's still missing.

| Policy check | Baremetal TDX (SHA-384) | Baremetal SNP (SHA-384) | Azure TDX (SHA-256) | Azure SNP (SHA-256) |
|---|---|---|---|---|
| 💾 Firmware (OVMF) | ✅ mr_td | ~~part of measur.~~ | ✅ mr_td | ~~snp_pcr03 (part of measur.)~~ |
| 💾 Launch digest | - | ✅ snp_launch_measurement | - | ✅ measurement |
| 💾 Kernel | ✅ tdvfkernel | ~~part of measur.~~ | - | - |
| 💾 Kernel cmdline | ✅ tdvfkernelparams | ~~part of measur.~~ | - | - |
| 💾 Initrd | ~~part of rtmr_2~~ | ~~part of measur.~~ | ✅ tdx_pcr09 | ✅ snp_pcr09 |
| 💾 Runtime register 1 | ✅ rtmr_1 | - | - | - |
| 💾 Runtime register 2 | ✅ rtmr_2 | - | - | - |
| 💾 UKI bundle | - | - | ✅ tdx_pcr11 | ✅ snp_pcr11 |
| 💾 Credentials | ~~pcr12~~ | - | ~~tdx_pcr12~~ | ~~snp_pcr12~~ |
| ⚙️ Init data | ~~init_data (mr_config_id)~~ | ~~init_data~~ | ~~tdx_pcr08~~ | ~~snp_pcr08~~ |
| 📋 TEE type | *"81000000"* | - | *"81000000"* | - |
| 📋 Vendor ID | *"939a72..."* | - | *"939a72..."* | - |
| 📋 TCB status | *"UpToDate"* | - | - | - |
| 📋 Collateral expiry | *"0"* | - | - | - |
| 📋 Debug policy | *false* | *false* | - | - |
| 📋 Migration policy | - | *false* | - | - |
| 🔒 CPU features (xfam) | ✅ xfam (--hw-xfam-allow) | - | ✅ xfam (--hw-xfam-allow) | - |
| 🔒 TCB version | - | 🔴 reported_tcb_* | - | 🔴 reported_tcb_* |
| 🔒 SMT policy | - | 🔴 platform_smt_enabled | - | 🔴 smt_enabled |
| 🔒 TSME | - | 🔴 platform_tsme_enabled | - | 🔴 tsme_enabled |
| 🔒 Guest ABI | - | 🔴 policy_abi_major/minor | - | 🔴 abi_major/minor |
| 🔒 Single socket | - | 🔴 policy_single_socket | - | 🔴 single_socket |
| 🔒 SMT allowed | - | 🔴 policy_smt_allowed | - | 🔴 smt_allowed |

✅ veritas computes (or accepts via CLI)<br>
🔴 not yet provided<br>
~~strikethrough~~ not individually checked (may be part of a combined value)<br>
\- does not exist

💾 software: pre-computable from artifacts<br>
⚙️ user config<br>
📋 policy checks against hardcoded values (no RVPS reference needed)<br>
🔒 hardware: platform-specific (see `--hw-*` flags)

### Being removed from upstream policy

These checks are being removed from the upstream default Rego policy.
Veritas does not output them.

| Policy check | Reason for removal |
|---|---|
| 🔒 SEAM module (mr_seam) | Redundant with tcb_status. TDX module hash is published by [Intel](https://github.com/intel/confidential-computing.tdx.tdx-module/releases) but impractical to discover from the BIOS vendor. |
| 🔒 TCB SVN (tcb_svn) | Already implicitly checked by the DCAP verifier as part of tcb_status. |

## Known limitations

See [Baremetal](BAREMETAL.md) and [Azure](AZURE.md) for
platform-specific limitations.

## TODO

- [ ] CI: validate RVPS keys against policy using OPA (detect missing keys and unused keys)

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE)
for details.
