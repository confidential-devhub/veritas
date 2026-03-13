# Baremetal

Veritas resolves the `rhel-coreos-extensions` image from the OCP
release payload, extracts the `kata-containers` and `edk2-ovmf` RPMs,
and computes reference values from the firmware, kernel, and initrd
binaries inside them.

Supports TDX and SNP.

## Usage

```
# TDX
veritas --platform baremetal --tee tdx --ocp-version 4.20.15 \
  --authfile pull-secret.json \
  --initdata initdata.toml

# SNP
veritas --platform baremetal --tee snp --ocp-version 4.20.15 \
  --authfile pull-secret.json \
  --initdata initdata.toml

# Multiple OCP versions (merged into one RVPS ConfigMap)
veritas --platform baremetal --tee tdx \
  --ocp-version 4.20.6 \
  --ocp-version 4.20.15 \
  --authfile pull-secret.json \
  --initdata initdata.toml

# With XFAM CPU features (TDX only, see below)
veritas --platform baremetal --tee tdx --ocp-version 4.20.15 \
  --authfile pull-secret.json \
  --initdata initdata.toml \
  --hw-xfam-allow x87 \
  --hw-xfam-allow sse \
  --hw-xfam-allow avx \
  --hw-xfam-allow avx512 \
  --hw-xfam-allow pkru \
  --hw-xfam-allow amx
```

## XFAM (CPU features)

The default attestation policy checks the `xfam` field from
the TDX quote. This is a bitmask of XSAVE CPU features enabled for
the TD guest. Use `--hw-xfam-allow` to specify which features to
include. Veritas computes the bitmask and outputs it in the format
the policy expects.

XFAM (eXtended Features Allowed Mask) controls which CPU instruction
set extensions are available inside the TD guest. Intel CPUs support
different extensions depending on the generation. For example, older
Xeons may not have AMX, while newer ones do.

Pass the features your CPU supports. For example, Intel Xeon Silver
4514Y: `x87 sse avx avx512 pkru amx`.

Run `veritas --help` for the full list of supported feature names.
See [Intel SDM Vol. 1, Chapter 13](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
for XSAVE state components per CPU generation.

> [!WARNING]
> If `--hw-xfam-allow` is not provided for TDX, veritas will not
> include xfam in the output and the default policy will
> fail the configuration trust claim.

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
veritas --platform baremetal --tee tdx --ocp-version 4.20.15 \
  --authfile pull-secret.json \
  --max-cpu-count 8
```

If your deployment uses a custom kernel command line (modified kata
configuration on the node), use `--kernel-cmdline` to pass the exact
string. This produces a single measurement value and skips the CPU
count iteration:

```
veritas --platform baremetal --tee tdx --ocp-version 4.20.15 \
  --authfile pull-secret.json \
  --kernel-cmdline "tsc=reliable no_timer_check ... nr_cpus=4 ..."
```

> [!WARNING]
> The `nr_cpus` parameter in the kernel command line is reportedly a
> legacy behavior from CPU hot-plug and may be removed upstream. If
> kata stops varying `nr_cpus`, this section and `--max-cpu-count`
> become unnecessary.

To find the current kernel command line on a node, check the kata
configuration at `/opt/kata/share/defaults/kata-containers/configuration-*.toml`
(the `kernel_params` field). Note that kata appends `nr_cpus=N` at
runtime based on the pod spec, so the config file alone is not the
complete cmdline.

## VM memory size

The `tdvfkernel` hash depends on the total VM memory size. This is
because RHEL's QEMU patches the kernel setup header before OVMF
measures it, writing the initrd load address into the header. That
address depends on where the initrd fits in the VM's memory layout,
which is determined by the total memory.

Veritas defaults to 2048 MB (kata default). If a pod gets a different
memory allocation, the hash won't match. Use `--mem-size` to override:

```
veritas --platform baremetal --tee tdx --ocp-version 4.20.15 \
  --authfile pull-secret.json \
  --mem-size 4096
```

The total VM memory size is the only factor. No layout, topology, or
allocation strategy is involved. Just one integer that determines the
initrd placement address.

> [!WARNING]
> `--mem-size` exists because RHEL's QEMU 9.1.0 patches the kernel
> setup header before OVMF measures it. To produce the correct hash,
> veritas vendors a Python port of QEMU's patching logic (based on
> [virtee/tdx-measure](https://github.com/virtee/tdx-measure)).
> An upstream QEMU fix skips this patching for TDX guests, making
> the hash independent of memory size. Once RHEL ships a QEMU with
> that fix, `--mem-size` and the vendored patching code become
> unnecessary and a plain PE hash of vmlinuz will suffice. RHEL
> backport date is TBD.
> TODO: find the exact upstream QEMU commit and track RHEL backport.

## Output example

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
          "... (one per nr_cpus)"
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
