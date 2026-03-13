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
| Azure (peer-pods) | TDX, SNP | osc-dm-verity-image (pre-computed PCRs) |
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
# Baremetal TDX for a single OCP version
veritas --platform baremetal --tee tdx --ocp-version 4.20.15 --authfile pull-secret.json

# Multiple OCP versions (merged into one RVPS ConfigMap)
veritas --platform baremetal --tee tdx --ocp-version 4.20.6 --ocp-version 4.20.15 --authfile pull-secret.json

# Include initdata hash
veritas --platform baremetal --tee tdx --ocp-version 4.20.15 --authfile pull-secret.json --initdata initdata.toml

# Include hardware xfam value from a live TDX quote. This value comes from
# the CPU/platform and cannot be pre-computed from software artifacts. Collect
# it once from a running TD (see "Collecting hardware values" below).
veritas --platform baremetal --tee tdx --ocp-version 4.20.15 --authfile pull-secret.json --hw-xfam e702060000000000

# Output to a specific directory
veritas --platform baremetal --tee tdx --ocp-version 4.20.15 --authfile pull-secret.json -o trustee-config/

# Azure peer-pods (latest dm-verity image)
veritas --platform azure --tee tdx --authfile pull-secret.json

# Azure with specific OSC versions (merged into one RVPS ConfigMap)
veritas --platform azure --tee tdx --osc-version 1.11.0 --osc-version 1.11.1 --authfile pull-secret.json

# Verbose output
veritas --platform baremetal --tee tdx --ocp-version 4.20.15 --authfile pull-secret.json -v
```

Output is written to the current directory by default.
Use `-o` to specify a different directory.

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
| 💾 Kernel ¹ | ✅ tdvfkernel | ~~part of measur.~~ | - | - |
| 💾 Kernel cmdline | ✅ tdvfkernelparams | ~~part of measur.~~ | - | - |
| 💾 Initrd | ~~initrd~~ | ~~part of measur.~~ | ~~tdx_pcr09~~ | ~~snp_pcr09~~ |
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
| 🔒 CPU features (xfam) | ✅ xfam (--hw-xfam) | - | ✅ xfam (--hw-xfam) | - |
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
🔒 hardware: needs live quote (collect once, pass via `--hw-*` flags)

### Being removed from upstream policy

These checks are being removed from the upstream default Rego policy.
Veritas does not output them.

| Policy check | Reason for removal |
|---|---|
| 🔒 SEAM module (mr_seam) | Redundant with tcb_status. TDX module hash is published by [Intel](https://github.com/intel/confidential-computing.tdx.tdx-module/releases) but impractical to discover from the BIOS vendor. |
| 🔒 TCB SVN (tcb_svn) | Already implicitly checked by the DCAP verifier as part of tcb_status. |

<small><i>¹ QEMU patches the kernel setup header (memory addresses, initrd location) before OVMF measures it. The hash depends on the VM memory layout, which may vary with different kata configurations. This is a known QEMU bug, already fixed upstream but not yet in RHEL. Once RHEL picks up the fix, a plain PE hash of vmlinuz will match.</i></small>

## Output example

### Baremetal TDX

```yaml
# Generated by veritas (platform: baremetal, tee: tdx)
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
          "2314211f527fb49d1e548228084c444dfe1c5221bd2f411f...",
          "a1b2c3d4e5f6...",
          "... (one per nr_cpus=1..32)"
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
      },
      {
        "name": "rtmr_1",
        "expiration": "2099-12-31T00:00:00Z",
        "value": [
          "bc875efe0e9f991c6072e3e1422e5e66e0e23c0addeaab16...",
          "... (one per nr_cpus, see 'Kernel command line and CPU counts')"
        ]
      },
      {
        "name": "rtmr_2",
        "expiration": "2099-12-31T00:00:00Z",
        "value": [
          "3c764645b39c6402b5c9f2df3d32eedf3b880ebc9de89bf3...",
          "... (one per nr_cpus)"
        ]
      },
      {
        "name": "xfam",
        "expiration": "2099-12-31T00:00:00Z",
        "value": [
          "e702060000000000"
        ]
      }
    ]
```

### Azure TDX

```yaml
# Generated by veritas (platform: azure, tee: tdx)
apiVersion: v1
kind: ConfigMap
metadata:
  name: rvps-reference-values
  namespace: trustee-operator-system
data:
  reference-values: |
    [
      {
        "name": "tdx_pcr03",
        "expiration": "2099-12-31T00:00:00Z",
        "value": [
          "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a..."
        ]
      },
      {
        "name": "tdx_pcr09",
        "expiration": "2099-12-31T00:00:00Z",
        "value": [
          "23ab4e921bc667fbb6703e9fbac6112a4857b37419d9faf9..."
        ]
      },
      {
        "name": "tdx_pcr11",
        "expiration": "2099-12-31T00:00:00Z",
        "value": [
          "d8a8eb2a682a687d879b48f8277d06fa16fed1b36d054d55..."
        ]
      },
      {
        "name": "tdx_pcr12",
        "expiration": "2099-12-31T00:00:00Z",
        "value": [
          "c1399c6e0f06bd74e43d3b3b474a97df09aa0d4e2f603e8f..."
        ]
      }
    ]
```

Apply directly with `oc apply -f rvps-reference-values.yaml`.

## Collecting hardware values

Some RVPS values come from the CPU/platform and cannot be pre-computed
from software artifacts. These must be collected once from a running TD
on the target hardware.

Currently the only hardware value veritas needs is `xfam` (the extended
features mask). To collect it:

1. Deploy a kata-cc pod with initdata pointing to Trustee (permissive
   policy recommended for ExecProcessRequest)
2. Trigger attestation from inside the pod:
   `curl http://127.0.0.1:8006/cdh/resource/default/attestation-status/status`
3. Read the xfam value from Trustee debug logs (`RUST_LOG=debug`),
   or from the parsed TDX quote body

The xfam value is stable for a given CPU generation and kata/QEMU
configuration. It only needs to be collected once per hardware platform.

> [!WARNING]
> **Baremetal TDX: xfam is required by the default attestation policy.**
> If `--hw-xfam` is not provided, veritas will not include xfam in the
> output and the default upstream policy will fail the configuration
> trust claim. Either pass `--hw-xfam` with a value collected from a
> live TD (see "Collecting hardware values" above), or customize the
> attestation policy to skip the xfam check.

## Kernel command line and CPU counts

The kernel command line is part of the attestation measurement. Kata
assembles it at VM creation time, and one of the parameters is
`nr_cpus=N`, which varies based on the pod's CPU resource request.
A pod requesting 4 CPUs will produce a different measurement than
one requesting 1.

By default, veritas generates reference values for every CPU count
from 1 to 32. This means cmdline-dependent keys (`tdvfkernelparams`,
`rtmr_1`, `rtmr_2` for TDX; `snp_launch_measurement` for SNP) will
have up to 32 values each. The attestation policy uses set membership
(`in`), so a pod with any CPU count in that range will pass.

To change the range, use `--max-cpu-count`:

```
# Generate for nr_cpus=1..8 instead of 1..32
veritas --platform baremetal --tee tdx --ocp-version 4.20.15 --authfile pull-secret.json --max-cpu-count 8
```

If your deployment uses a custom kernel command line (modified kata
configuration on the node), use `--kernel-cmdline` to pass the exact
string. This produces a single measurement value and skips the CPU
count iteration:

```
veritas --platform baremetal --tee tdx --ocp-version 4.20.15 --authfile pull-secret.json \
  --kernel-cmdline "tsc=reliable no_timer_check ... nr_cpus=4 ..."
```

To find the current kernel command line on a node, check the kata
configuration at `/opt/kata/share/defaults/kata-containers/configuration-*.toml`
(the `kernel_params` field). Note that kata appends `nr_cpus=N` at
runtime based on the pod spec, so the config file alone is not the
complete cmdline.

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

**tdvfkernel hash depends on VM memory size.** The QEMU patching
writes the initrd address into the kernel header, and that address
depends on the VM memory layout. Veritas defaults to 2 GB (kata
default). If the VM gets a different memory allocation, the hash
won't match. Use `--mem-size` to override (not yet implemented).
This goes away when RHEL picks up the upstream QEMU fix that
stops patching the kernel for TDX guests.
TODO: track when the RHEL QEMU fix lands.

**nr_cpus varies the kernel cmdline.** Kata sets `nr_cpus=N` on
the kernel command line based on the pod's CPU request, producing
different measurements per CPU count. Veritas generates one value
per nr_cpus (1..32) to cover all variants. This is reportedly a
legacy behavior from CPU hot-plug and should be fixed upstream.
TODO: track when kata stops varying nr_cpus in the cmdline.

## TODO

### High priority

- [x] Remove cluster dependency: resolve extension image by OCP version, verify release payload, no kubeconfig needed
- [x] Support multiple OCP/OSC versions with merged reference values
- [x] Add `--kernel-cmdline` flag and `--max-cpu-count` for cmdline-dependent measurements

### Other

- [ ] Remove vendored QEMU patching logic once RHEL ships a fixed QEMU
- [x] Accept hardware xfam value via `--hw-xfam` flag
- [ ] Add `--xfam-allow` to compute xfam bitmask from feature names (e.g. `--xfam-allow x87,sse,avx,avx512,amx`), replacing `--hw-xfam` as the recommended path
- [ ] Add `--mem-size` to override the default 2 GB VM memory assumption for tdvfkernel hash
- [ ] Drop standalone `initrd` from RVPS output (pending: clarify if OVMF measures initrd as a separate UEFI event on Red Hat baremetal)
- [ ] Investigate downstream policy PCR checks ([openshift/trustee-operator#291](https://github.com/openshift/trustee-operator/pull/291)): adds pcr03, pcr08, pcr09, pcr12 for Azure SNP/TDX
- [ ] CI: validate RVPS keys against policy using OPA (detect missing keys and unused keys)
- [ ] CGPU (Confidential GPU) support

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE)
for details.
