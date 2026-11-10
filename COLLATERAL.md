# Attestation collateral

> [!NOTE]
> Only needed when Trustee cannot reach the CPU vendor services
> (`kdsintf.amd.com` for AMD, `api.trustedservices.intel.com` for
> Intel). In connected environments Trustee downloads collateral by
> itself.

To verify a confidential pod, Trustee checks the CPU signature on the
attestation report. For that it needs certificates and data published by
the CPU vendor, called collateral:

- **AMD SEV-SNP**: the VCEK certificate, one per CPU chip and firmware
  version.
- **Intel TDX**: TCB info, QE identity and revocation lists, one set per
  platform family, valid for up to 30 days.

In a disconnected environment Trustee cannot download collateral, so you
have to provide it, unless it comes with the attestation evidence.
`veritas collateral` automates this.

Collateral only lets Trustee check the report signature. The pod must
still match the attestation policy and the RVPS reference values.

## Prerequisites

- `oc` logged in to the workload cluster as cluster-admin (`collect` uses
  `oc debug node`).
- The nodes can pull `quay.io/openshift_sandboxed_containers/coco-tools`
  (mirrored with the OSC images in disconnected clusters).
- `render` and `verify`: run veritas from the coco-tools image, which
  ships the vendor tools it uses. Otherwise install `veritas[snp]` and
  `snpguest` (AMD) or Intel's `pcsclient` (Intel).
- The connected workstation can reach the vendor services listed above.

## Steps

The same steps for every TEE and platform:

| Step | Where | Bare metal Intel | Bare metal AMD | Azure Intel | Azure AMD |
|---|---|:-:|:-:|:-:|:-:|
| [1. Collect](#1-collect-node-identifiers) | Workload cluster | `collect` | `collect` | `collect` | - |
| [2. Render](#2-render-the-manifests) 🌐 | Connected workstation | `render` | `render` | `render` | - |
| [3. Apply](#3-apply-to-the-trustee-cluster) | Trustee cluster | `oc apply` + `oc patch`<br>config map edit, once | `oc apply` + `oc patch` | `oc apply` + `oc patch`<br>config map edit, once | - |
| [4. Verify](#4-verify) | Anywhere | `verify` | `verify` | `verify` | - |

🌐 needs internet. Azure AMD needs nothing: the collateral comes with
the attestation evidence.

By default the workload cluster and the Trustee cluster are different
clusters. Veritas never changes either of them: it reads the workload
cluster and writes files that you apply to the Trustee cluster.

### 1. Collect node identifiers

On the bastion, logged in to the **workload cluster**:

```bash
veritas collateral collect --selector node-role.kubernetes.io/worker= -o request.json
```

Detects the TEE of each node and reads what is needed to download its
collateral. It only reads from the cluster, and asks for confirmation
first (`--yes` to skip). Use `--node NAME` instead of `--selector` to
pick nodes by name.

`request.json` contains no secrets. Copy it to the connected workstation.

### 2. Render the manifests

On the connected workstation:

```bash
veritas collateral render request.json -o manifests/ --verify [--kbsconfig kbsconfig.json]
```

Downloads the collateral from the CPU vendor, checks it, and writes the
manifests for Trustee:

- `manifests/secrets.yaml`: Secrets holding the collateral.
- `manifests/kbsconfig.patch`: the KbsConfig change that mounts them.

`--kbsconfig` is optional: it keeps the Secrets already mounted in the
KbsConfig. To get it, on the bastion logged in to the **Trustee
cluster**:

```bash
oc get kbsconfig <name> -n trustee-operator-system -o json > kbsconfig.json
```

> [!WARNING]
> Without `--kbsconfig`, the patch replaces any Secrets already mounted
> in `kbsLocalCertCacheSpec`.

### 3. Apply to the Trustee cluster

Copy `manifests/` to the bastion and, logged in to the **Trustee
cluster**, run the commands printed by `render`:

```bash
oc apply --server-side -f manifests/secrets.yaml
oc patch kbsconfig <name> -n trustee-operator-system --type merge --patch-file manifests/kbsconfig.patch
```

For Intel, the first time only, also point Trustee to the collateral
file. In the KBS config map (`spec.kbsConfigMapName` of the KbsConfig),
set:

```toml
[attestation_service.verifier_config.dcap_verifier]
collateral_service = "file:///opt/confidential-containers/attestation-service/tdx/platform_collaterals.json"
```

Then restart Trustee.

### 4. Verify

```bash
veritas collateral verify request.json manifests/
```

Checks offline that the manifests cover every node and are still valid,
and shows when the collateral expires:

```
worker-0   snp   ok     VCEK expires 2033-10-04
worker-1   snp   FAIL   missing Secret vcek-c38427a30d4c7af9
worker-2   tdx   ok     collateral expires 2026-11-06
```

It exits non-zero if any node fails.

## Keeping it up to date

Collateral must be refreshed when:

- it expires (for TDX, every month at most);
- a node firmware is updated (SNP);
- a node is added (SNP).

`verify` detects all three and shows when the collateral expires, so run
it regularly:

```bash
veritas collateral collect --selector node-role.kubernetes.io/worker= -o request.json
veritas collateral verify request.json manifests/
```

If a node fails, repeat steps 2 and 3.

> [!TIP]
> `verify` needs no internet, so you only go to the connected
> workstation when something actually changed.
