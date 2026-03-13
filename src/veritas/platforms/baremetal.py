"""Baremetal platform reference value extraction."""

import hashlib
import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

from veritas.vendor.td_payload_qemu_hash import compute_kernel_hash
from veritas.vendor.td_shim_tee_info_hash import compute_mrtd
from veritas.models import ReferenceValue
from veritas.platforms.base import PlatformExtractor

log = logging.getLogger(__name__)

# Default kernel command line from kata config.
# Contains {nr_cpus} placeholder, substituted per CPU count.
DEFAULT_KERNEL_CMDLINE = (
    "tsc=reliable no_timer_check rcupdate.rcu_expedited=1 "
    "i8042.direct=1 i8042.dumbkbd=1 i8042.nopnp=1 i8042.noaux=1 "
    "noreplace-smp reboot=k cryptomgr.notests net.ifnames=0 "
    "pci=lastbus=0 console=hvc0 console=hvc1 debug panic=1 "
    "nr_cpus={nr_cpus} selinux=0 scsi_mod.scan=none agent.log=debug "
    "cgroup_no_v1=all systemd.unified_cgroup_hierarchy=1"
)


class BaremetalExtractor(PlatformExtractor):
    """Extract reference values from kata artifacts in rhel-coreos-extensions."""

    EVIDENCE_TYPES = {
        "tdx": "tdx",
        "snp": "snp",
    }

    KATA_RPM_GLOB = "kata-containers-*.rpm"
    EDK2_RPM_GLOB = "edk2-ovmf-*.rpm"
    EXTENSIONS_PATH = "/usr/share/rpm-ostree/extensions"

    OCP_RELEASE_REPO = "quay.io/openshift-release-dev/ocp-release"

    def __init__(self, tee, authfile=None, ocp_versions=None,
                 kernel_cmdline=None, max_cpu_count=32, mem_size=0x80000000):
        if tee not in self.EVIDENCE_TYPES:
            raise ValueError(f"Unknown TEE: {tee}. Must be one of {list(self.EVIDENCE_TYPES)}")
        if not ocp_versions:
            raise ValueError("At least one --ocp-version is required for baremetal")
        self.tee = tee
        self.authfile = authfile
        self.ocp_versions = ocp_versions
        self.kernel_cmdline = kernel_cmdline
        self.max_cpu_count = max_cpu_count
        self.mem_size = mem_size

    def _kernel_cmdlines(self):
        """Return list of kernel cmdlines to compute measurements for.

        If --kernel-cmdline was provided, returns just that cmdline.
        Otherwise generates one per CPU count using the default template.
        """
        if self.kernel_cmdline:
            return [self.kernel_cmdline]
        return [
            DEFAULT_KERNEL_CMDLINE.format(nr_cpus=n)
            for n in range(1, self.max_cpu_count + 1)
        ]

    @property
    def platform(self) -> str:
        return "baremetal"

    @property
    def evidence_type(self) -> str:
        return self.EVIDENCE_TYPES[self.tee]

    def extract(self) -> list[ReferenceValue]:
        """Resolve extensions image per OCP version, extract RPMs, and compute hashes."""
        merged = {}
        for version in self.ocp_versions:
            log.info("Processing OCP %s", version)
            self._verify_release(version)
            image_ref = self._get_extensions_image(version)
            log.info("Extensions image: %s", image_ref)

            with tempfile.TemporaryDirectory() as tmpdir:
                self._extract_extensions(image_ref, tmpdir)
                values = self._extract_and_compute(tmpdir)

            for v in values:
                if v.name in merged:
                    for val in v.values:
                        if val not in merged[v.name].values:
                            merged[v.name].values.append(val)
                else:
                    merged[v.name] = v
        return list(merged.values())

    def compute_initdata(self, initdata_path: str) -> ReferenceValue:
        """Compute initdata hash for baremetal TDX (sha384)."""
        content = Path(initdata_path).read_bytes()
        digest = hashlib.sha384(content).hexdigest()
        return ReferenceValue(
            name="init_data",
            values=[digest],
            category="configuration",
            description="Init data hash",
            algorithm="sha384",
            source="computed from initdata.toml",
        )

    def _verify_release(self, ocp_version: str):
        """Verify the OCP release payload integrity."""
        release_image = f"{self.OCP_RELEASE_REPO}:{ocp_version}-x86_64"
        cmd = ["oc", "adm", "release", "info", "--verify", release_image]
        if self.authfile:
            cmd.extend(["-a", self.authfile])
        log.info("Verifying OCP %s release payload...", ocp_version)
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"Release verification failed for OCP {ocp_version}:\n{result.stderr}")
        log.info("Release verified: %s", result.stdout.strip())

    def _get_extensions_image(self, ocp_version: str) -> str:
        """Get rhel-coreos-extensions image ref from the OCP release."""
        release_image = f"{self.OCP_RELEASE_REPO}:{ocp_version}-x86_64"
        cmd = [
            "oc", "adm", "release", "info",
            "--image-for=rhel-coreos-extensions",
            release_image,
        ]
        if self.authfile:
            cmd.extend(["-a", self.authfile])
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"Failed to get extensions image for OCP {ocp_version}:\n{result.stderr}")
        return result.stdout.strip()

    def _extract_extensions(self, image_ref, dest_dir):
        """Extract the RPM extensions directory from the image using oc."""
        cmd = [
            "oc", "image", "extract", image_ref,
            f"--path={self.EXTENSIONS_PATH}/:{dest_dir}",
        ]
        if self.authfile:
            cmd.extend(["-a", self.authfile])
        log.info("Extracting extensions from %s", image_ref)
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"Failed to extract extensions:\n{result.stderr}")

    def _extract_and_compute(self, extensions_dir) -> list[ReferenceValue]:
        """Extract RPMs, find artifacts, and compute values."""
        artifacts = {}
        rpm_dir = Path(extensions_dir)

        with tempfile.TemporaryDirectory() as extract_dir:
            kata_rpms = list(rpm_dir.glob(self.KATA_RPM_GLOB))
            if not kata_rpms:
                raise RuntimeError(f"No {self.KATA_RPM_GLOB} found in extensions")
            log.info("Found kata RPM: %s", kata_rpms[0].name)
            self._extract_rpm(kata_rpms[0], extract_dir)

            edk2_rpms = list(rpm_dir.glob(self.EDK2_RPM_GLOB))
            if not edk2_rpms:
                raise RuntimeError(f"No {self.EDK2_RPM_GLOB} found in extensions")
            log.info("Found edk2 RPM: %s", edk2_rpms[0].name)
            self._extract_rpm(edk2_rpms[0], extract_dir)

            extract_path = Path(extract_dir)

            vmlinuz_candidates = list(extract_path.rglob("osbuilder-images/*/vmlinuz"))
            if vmlinuz_candidates:
                artifacts["vmlinuz"] = vmlinuz_candidates[0]
                log.info("Found vmlinuz: %s", artifacts["vmlinuz"])

            initrd_candidates = list(extract_path.rglob("osbuilder-images/*/kata-cc.initrd"))
            if initrd_candidates:
                artifacts["initrd"] = initrd_candidates[0]
                log.info("Found initrd: %s", artifacts["initrd"])

            ovmf_tdx = list(extract_path.rglob("OVMF.inteltdx.fd"))
            if ovmf_tdx:
                artifacts["ovmf_tdx"] = ovmf_tdx[0]
                log.info("Found OVMF.inteltdx.fd: %s", artifacts["ovmf_tdx"])

            ovmf_snp = list(extract_path.rglob("OVMF.amdsev.fd"))
            if ovmf_snp:
                artifacts["ovmf_snp"] = ovmf_snp[0]
                log.info("Found OVMF.amdsev.fd: %s", artifacts["ovmf_snp"])

            if self.tee == "tdx":
                return self._compute_tdx_values(artifacts)
            else:
                return self._compute_snp_values(artifacts)

    def _compute_tdx_values(self, artifact_paths: dict) -> list[ReferenceValue]:
        """Compute TDX reference values."""
        values = []

        initrd_size = 0
        if "initrd" in artifact_paths:
            initrd_size = artifact_paths["initrd"].stat().st_size

        if "vmlinuz" in artifact_paths:
            digest = compute_kernel_hash(
                str(artifact_paths["vmlinuz"]),
                initrd_size=initrd_size,
                mem_size=self.mem_size,
            )
            values.append(ReferenceValue(
                name="tdvfkernel",
                values=[digest],
                category="executables",
                description="Kernel binary (vmlinuz) digest from UEFI event log",
                algorithm="sha384",
                source="kata-containers RPM (PE Authenticode hash, QEMU-patched)",
            ))

        cmdlines = self._kernel_cmdlines()
        # TDX UEFI event log measures the cmdline with "initrd=initrd" suffix
        # and null terminator, encoded as UTF-16-LE.
        cmdline_hashes = []
        for cmdline in cmdlines:
            tdx_cmdline = cmdline + " initrd=initrd\x00"
            h = hashlib.sha384(tdx_cmdline.encode("utf-16-le")).hexdigest()
            if h not in cmdline_hashes:
                cmdline_hashes.append(h)
        source = "kernel cmdline (--kernel-cmdline)" if self.kernel_cmdline else \
            f"default kata cmdline, nr_cpus=1..{self.max_cpu_count}"
        values.append(ReferenceValue(
            name="tdvfkernelparams",
            values=cmdline_hashes,
            category="executables",
            description="Kernel command line (UTF-16-LE) digest from UEFI event log",
            algorithm="sha384",
            source=source,
        ))

        if "initrd" in artifact_paths:
            initrd_data = artifact_paths["initrd"].read_bytes()
            initrd_hash = hashlib.sha384(initrd_data).hexdigest()
            values.append(ReferenceValue(
                name="initrd",
                values=[initrd_hash],
                category="executables",
                description="Initrd (kata-cc.initrd) digest from UEFI event log",
                algorithm="sha384",
                source="kata-containers RPM (sha384 of file)",
            ))

        mr_td = self._compute_mr_td(artifact_paths.get("ovmf_tdx"))
        if mr_td:
            values.append(mr_td)

        rtmrs = self._compute_rtmrs(artifact_paths)
        values.extend(rtmrs)

        return values

    def _compute_snp_values(self, artifact_paths: dict) -> list[ReferenceValue]:
        """Compute SNP launch measurement using sev-snp-measure.

        Runs sev-snp-measure once per kernel cmdline variant. The vcpus
        parameter also varies with nr_cpus since kata sets both together.
        """
        ovmf = artifact_paths.get("ovmf_snp")
        vmlinuz = artifact_paths.get("vmlinuz")
        initrd = artifact_paths.get("initrd")

        if not all([ovmf, vmlinuz, initrd]):
            missing = [k for k in ("ovmf_snp", "vmlinuz", "initrd") if k not in artifact_paths]
            raise RuntimeError(f"Missing artifacts for SNP measurement: {missing}")

        try:
            from sevsnpmeasure.guest import snp_calc_launch_digest
            from sevsnpmeasure.vcpu_types import CPU_SIGS
        except ImportError:
            raise RuntimeError("sev-snp-measure is not installed (pip install sev-snp-measure)")

        import base64
        cmdlines = self._kernel_cmdlines()
        measurements = []

        for cmdline in cmdlines:
            # Extract nr_cpus from cmdline for vcpus param, default to 1
            vcpus = 1
            for part in cmdline.split():
                if part.startswith("nr_cpus="):
                    try:
                        vcpus = int(part.split("=", 1)[1])
                    except ValueError:
                        pass
                    break

            ld = snp_calc_launch_digest(
                vcpus=vcpus,
                vcpu_sig=CPU_SIGS["EPYC-v4"],
                ovmf_file=str(ovmf),
                kernel=str(vmlinuz),
                initrd=str(initrd),
                append=cmdline,
                guest_features=0x1,
                ovmf_hash_str="",
            )
            m = base64.b64encode(ld).decode()
            if m not in measurements:
                measurements.append(m)

        log.info("Computed SNP measurements for %d cmdline variant(s), "
                 "%d unique", len(cmdlines), len(measurements))

        return [ReferenceValue(
            name="snp_launch_measurement",
            values=measurements,
            category="executables",
            description="SNP launch measurement (OVMF + kernel + initrd + cmdline)",
            algorithm="sha384",
            source="sev-snp-measure",
        )]

    def _compute_rtmrs(self, artifact_paths: dict) -> list[ReferenceValue]:
        """Compute RTMR1 and RTMR2 using tdx-measure --runtime-only.

        Runs tdx-measure once per kernel cmdline variant (one per CPU count,
        or a single user-provided cmdline). Merges unique values.
        """
        if not shutil.which("tdx-measure"):
            log.warning("tdx-measure not found, skipping RTMR computation")
            return []

        vmlinuz = artifact_paths.get("vmlinuz")
        initrd = artifact_paths.get("initrd")
        if not vmlinuz or not initrd:
            log.warning("Missing kernel or initrd, skipping RTMR computation")
            return []

        cmdlines = self._kernel_cmdlines()
        rtmr1_values = []
        rtmr2_values = []

        for cmdline in cmdlines:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmpdir = Path(tmpdir)
                kernel_link = tmpdir / "vmlinuz"
                initrd_link = tmpdir / "kata-cc.initrd"
                kernel_link.symlink_to(vmlinuz)
                initrd_link.symlink_to(initrd)

                metadata = {
                    "direct": {
                        "kernel": "vmlinuz",
                        "initrd": "kata-cc.initrd",
                        "cmdline": cmdline,
                    }
                }
                metadata_path = tmpdir / "metadata.json"
                metadata_path.write_text(json.dumps(metadata))

                result = subprocess.run(
                    ["tdx-measure", str(metadata_path), "--runtime-only", "--json"],
                    capture_output=True, text=True,
                )
                if result.returncode != 0:
                    log.warning("tdx-measure failed: %s", result.stderr.strip())
                    return []

                measurements = json.loads(result.stdout)

            if measurements.get("rtmr1") and measurements["rtmr1"] not in rtmr1_values:
                rtmr1_values.append(measurements["rtmr1"])
            if measurements.get("rtmr2") and measurements["rtmr2"] not in rtmr2_values:
                rtmr2_values.append(measurements["rtmr2"])

        log.info("Computed RTMRs for %d cmdline variant(s), "
                 "%d unique rtmr_1, %d unique rtmr_2",
                 len(cmdlines), len(rtmr1_values), len(rtmr2_values))

        values = []
        if rtmr1_values:
            values.append(ReferenceValue(
                name="rtmr_1",
                values=rtmr1_values,
                category="executables",
                description="Runtime measurement register 1 (kernel + boot services)",
                algorithm="sha384",
                source="tdx-measure --runtime-only",
            ))
        if rtmr2_values:
            values.append(ReferenceValue(
                name="rtmr_2",
                values=rtmr2_values,
                category="executables",
                description="Runtime measurement register 2 (kernel cmdline + initrd)",
                algorithm="sha384",
                source="tdx-measure --runtime-only",
            ))
        return values

    def _compute_mr_td(self, ovmf_path) -> ReferenceValue | None:
        """Compute mr_td from OVMF binary using TDVF descriptor."""
        if not ovmf_path:
            return None
        try:
            mr_td_value = compute_mrtd(str(ovmf_path))
        except (ValueError, IOError) as e:
            log.warning("Failed to compute mr_td: %s", e)
            return None
        log.info("mr_td: %s", mr_td_value)
        return ReferenceValue(
            name="mr_td",
            values=[mr_td_value],
            category="executables",
            description="TD build-time measurement (OVMF/TDVF)",
            algorithm="sha384",
            source="TDVF descriptor from OVMF.inteltdx.fd",
        )

    @staticmethod
    def _extract_rpm(rpm_path, dest_dir):
        """Extract an RPM to a destination directory."""
        result = subprocess.run(
            f"cd {dest_dir} && rpm2cpio {rpm_path} | cpio -idm",
            shell=True, capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Failed to extract {rpm_path}:\n{result.stderr}")
