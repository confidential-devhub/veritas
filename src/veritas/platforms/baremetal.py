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
from veritas.vendor.kata_config import (
    KataConfigError,
    KataGuestConfig,
    cmdline_variants,
)
from veritas.platforms.utils import remap_registry

log = logging.getLogger(__name__)


class BaremetalExtractor(PlatformExtractor):
    """Extract reference values from kata artifacts in rhel-coreos-extensions."""

    EVIDENCE_TYPES = {
        "tdx": "tdx",
        "snp": "snp",
    }

    # RPM subdirectory that carries the configuration.toml for each runtime
    # class a measurement is generated for. The runtime class the cluster
    # actually uses maps onto these (on OpenShift, RuntimeClass kata-cc
    # handler=kata-tdx on a TDX machine, kata-cc-nvidia-gpu
    # handler=kata-tdx-nvidia-gpu).
    RUNTIME_CLASS_DIRS = {
        "tdx": {"default": "kata-tdx", "gpu": "kata-tdx-nvidia-gpu"},
        "snp": {"default": "kata-snp", "gpu": "kata-snp-nvidia-gpu"},
    }

    KATA_RPM_GLOB = "kata-containers-*.rpm"
    EDK2_RPM_GLOB = "edk2-ovmf-*.rpm"
    EXTENSIONS_PATH = "/usr/share/rpm-ostree/extensions"
    INITRD_GLOB = "osbuilder-images/*/kata-cc.initrd"
    GPU_INITRD_GLOB = "osbuilder-images/*/kata-*gpu*.initrd"

    OCP_RELEASE_REPO = "quay.io/openshift-release-dev/ocp-release"

    def __init__(self, tee, authfile=None, ocp_versions=None,
                 kernel_cmdline=None, max_cpu_count=32, mem_size=0x80000000,
                 kata_rpm=None, gpu=False, mirror_registry=None):
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
        self.kata_rpm = Path(kata_rpm) if kata_rpm else None
        self.gpu = gpu
        self.ocp_release_repo = remap_registry(self.OCP_RELEASE_REPO, mirror_registry)
        self.mirror_registry = mirror_registry
        # Guest cmdline configuration per runtime class, parsed from the
        # configuration.toml inside the kata RPM ("default" / "gpu" keys).
        self._guest_configs: dict[str, KataGuestConfig] = {}
        if self.kata_rpm and not self.kata_rpm.exists():
            raise ValueError(f"Kata RPM not found: {self.kata_rpm}")

    def _kernel_cmdlines(self, is_gpu=False):
        """Return list of kernel cmdlines to compute measurements for.

        If --kernel-cmdline was provided, returns just that cmdline.
        Otherwise reconstructs the command line kata-runtime assembles from
        the configuration.toml shipped in the kata RPM (see
        veritas.vendor.kata_config), one variant per CPU count.

        Args:
            is_gpu: If True, uses the GPU runtime class config. Ignored if
                --kernel-cmdline is set.
        """
        if self.kernel_cmdline:
            return [self.kernel_cmdline]

        return cmdline_variants(self._guest_config(is_gpu), self.max_cpu_count)

    def _guest_config(self, is_gpu: bool) -> KataGuestConfig:
        """Guest cmdline config for the runtime class, or a clear error.

        The default runtime class is required, so a missing config raises
        KataConfigError (the caller skips the whole OCP version). The optional
        GPU class is pre-checked by the caller instead, so it never reaches the
        error path here.
        """
        key = "gpu" if is_gpu else "default"
        cfg = self._guest_configs.get(key)
        if cfg is None:
            class_dir = self.RUNTIME_CLASS_DIRS[self.tee][key]
            raise KataConfigError(
                "cannot reconstruct the guest kernel command line: no "
                f"configuration.toml for runtime class directory '{class_dir}' "
                "was found in the kata RPM. Pass --kernel-cmdline to specify "
                "the command line manually."
            )
        return cfg

    def _parse_guest_configs(self, extract_path: Path):
        """Parse the per-runtime-class configuration.toml from the kata RPM.

        The configs live next to the kernel/initrd artifacts veritas already
        extracts (etc/kata-containers/<class>/configuration.toml), so the
        generated measurements are derived from the same approved
        configuration the runtime uses.
        """
        self._guest_configs = {}
        class_dirs = self.RUNTIME_CLASS_DIRS[self.tee]
        for key, class_dir in class_dirs.items():
            matches = list(extract_path.glob(f"etc/kata-containers/{class_dir}/configuration.toml"))
            if not matches:
                continue
            self._guest_configs[key] = KataGuestConfig.from_toml(matches[0])
            log.info("Parsed guest cmdline config (%s): %s", key, matches[0])

    @property
    def platform(self) -> str:
        return "baremetal"

    @property
    def evidence_type(self) -> str:
        return self.EVIDENCE_TYPES[self.tee]

    def reference_key_names(self) -> set[str]:
        if self.tee == "tdx":
            return {"tdvfkernel", "tdvfkernelparams", "mr_td", "rtmr_1",
                    "rtmr_2", "init_data", "xfam"}
        return {"snp_launch_measurement", "init_data"}

    CACHE_DIR = Path.home() / ".cache" / "veritas" / "extensions"

    def _cache_path(self, image_ref: str) -> Path | None:
        """Return cache path for an image ref, or None if no digest found."""
        if "@sha256:" not in image_ref:
            return None
        digest = image_ref.split("@sha256:", 1)[1]
        return self.CACHE_DIR / digest

    def extract(self) -> list[ReferenceValue]:
        """Resolve extensions image per OCP version, extract RPMs, and compute hashes."""
        merged = {}
        self.skipped_versions = []
        for version in self.ocp_versions:
            log.info("Processing OCP %s", version)
            self._verify_release(version)
            image_ref = self._get_extensions_image(version)
            log.info("Extensions image: %s", image_ref)

            try:
                cache = self._cache_path(image_ref)
                if cache and cache.exists():
                    log.info("Using cached extensions: %s", cache)
                    values = self._extract_and_compute(str(cache))
                else:
                    with tempfile.TemporaryDirectory() as tmpdir:
                        self._extract_extensions(image_ref, tmpdir)
                        values = self._extract_and_compute(tmpdir)
                        if cache:
                            cache.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copytree(tmpdir, cache)
                            log.info("Cached extensions: %s", cache)
            except KataConfigError as e:
                # This version's kata RPM carries no usable configuration.toml
                # for the required runtime class; skip it rather than abort the
                # whole run and discard values already computed for other
                # versions. Pass --kernel-cmdline to handle it manually.
                log.warning("Skipping OCP %s: %s", version, e)
                self.skipped_versions.append(version)
                continue

            if not values:
                self.skipped_versions.append(version)
                continue

            for v in values:
                if v.name in merged:
                    for val in v.values:
                        if val not in merged[v.name].values:
                            merged[v.name].values.append(val)
                else:
                    merged[v.name] = v
        return list(merged.values())

    def compute_initdata(self, initdata_paths: list[str]) -> ReferenceValue:
        """Compute initdata hash using the algorithm declared in the initdata.toml header."""
        import tomllib
        digests = []
        algo = None
        for p in initdata_paths:
            content = Path(p).read_bytes()
            try:
                file_algo = tomllib.loads(content.decode()).get("algorithm", "sha384").lower()
            except Exception:
                file_algo = "sha384"
                log.warning("Could not parse algorithm from %s, defaulting to sha384", p)
            if algo is not None and file_algo != algo:
                log.warning("Mixed algorithms across initdata files (%s vs %s), using %s",
                            algo, file_algo, file_algo)
            algo = file_algo
            digests.append(hashlib.new(algo, content).hexdigest())
        sources = ", ".join(Path(p).name for p in initdata_paths)
        return ReferenceValue(
            name="init_data",
            values=digests,
            category="configuration",
            description="Init data hash",
            algorithm=algo,
            source=f"computed from {sources}",
        )

    def _verify_release(self, ocp_version: str):
        """Verify the OCP release payload integrity."""
        release_image = f"{self.ocp_release_repo}:{ocp_version}-x86_64"
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
        release_image = f"{self.ocp_release_repo}:{ocp_version}-x86_64"
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
        return remap_registry(result.stdout.strip(), self.mirror_registry)

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
            if self.kata_rpm:
                log.info("Using custom kata RPM: %s", self.kata_rpm)
                self._extract_rpm(self.kata_rpm, extract_dir)
            else:
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

            # Guest cmdlines are derived from the RPM's own configuration
            # (needed before any measurement is computed).
            self._parse_guest_configs(extract_path)

            vmlinuz_candidates = list(extract_path.rglob("osbuilder-images/*/vmlinuz"))
            if vmlinuz_candidates:
                artifacts["vmlinuz"] = vmlinuz_candidates[0]
                log.info("Found vmlinuz: %s", artifacts["vmlinuz"])

            # Detect regular initrd
            initrd_candidates = list(extract_path.rglob(self.INITRD_GLOB))
            if initrd_candidates:
                artifacts["initrd"] = initrd_candidates[0]
                log.info("Found initrd: %s", artifacts["initrd"])

            # Detect GPU initrds (there may be cc and non-cc variants)
            gpu_initrd_candidates = list(extract_path.rglob(self.GPU_INITRD_GLOB))
            artifacts["gpu_initrds"] = gpu_initrd_candidates
            for g in gpu_initrd_candidates:
                log.info("Found GPU initrd: %s", g)

            ovmf_tdx = list(extract_path.rglob("OVMF.inteltdx.fd"))
            if ovmf_tdx:
                artifacts["ovmf_tdx"] = ovmf_tdx[0]
                log.info("Found OVMF.inteltdx.fd: %s", artifacts["ovmf_tdx"])

            ovmf_snp = list(extract_path.rglob("OVMF.amdsev.fd"))
            if ovmf_snp:
                artifacts["ovmf_snp"] = ovmf_snp[0]
                log.info("Found OVMF.amdsev.fd: %s", artifacts["ovmf_snp"])

            if "vmlinuz" not in artifacts:
                log.error("Missing vmlinuz in kata RPM. Cannot compute measurements.")
                return []

            # Compute measurements based on --kernel-cmdline and --gpu flags
            if self.kernel_cmdline:
                # Manual mode: use specified cmdline with appropriate initrd
                if self.gpu and not artifacts["gpu_initrds"]:
                    log.error("--gpu specified but no GPU initrd found in kata RPM")
                    return []
                if not self.gpu and "initrd" not in artifacts:
                    log.error("No regular initrd found in kata RPM")
                    return []

                if self.gpu:
                    all_values = []
                    for gpu_initrd in artifacts["gpu_initrds"]:
                        log.info("Using GPU initrd with custom cmdline: %s", gpu_initrd.name)
                        variant = artifacts.copy()
                        variant["initrd"] = gpu_initrd
                        all_values.extend(self._compute_tdx_values(variant, is_gpu=True)
                                          if self.tee == "tdx"
                                          else self._compute_snp_values(variant, is_gpu=True))
                    return all_values
                else:
                    log.info("Using regular initrd with custom cmdline")
                    return self._compute_values_for_variant(artifacts, "initrd", is_gpu=False)
            else:
                # Auto mode: generate for available variants
                all_values = []

                if "initrd" in artifacts:
                    log.info("Generating measurements for regular (non-GPU) pods")
                    all_values.extend(self._compute_values_for_variant(artifacts, "initrd", is_gpu=False))

                # The GPU runtime class is optional: a missing GPU config only
                # means this cluster cannot run GPU pods, so skip that subset
                # and keep the regular-pod values. (A missing *default* config,
                # by contrast, leaves nothing to measure and raises
                # KataConfigError, skipping the whole version.) Either way we
                # never guess a cmdline.
                gpu_initrds = artifacts["gpu_initrds"]
                if gpu_initrds and "gpu" not in self._guest_configs:
                    gpu_dir = self.RUNTIME_CLASS_DIRS[self.tee]["gpu"]
                    log.warning(
                        "Skipping GPU pod measurements: no configuration.toml "
                        "for GPU runtime class directory '%s' in the kata RPM "
                        "(found %d GPU initrd(s))", gpu_dir, len(gpu_initrds))
                    gpu_initrds = []
                for gpu_initrd in gpu_initrds:
                    log.info("Generating measurements for GPU pods: %s", gpu_initrd.name)
                    variant = artifacts.copy()
                    variant["initrd"] = gpu_initrd
                    all_values.extend(self._compute_tdx_values(variant, is_gpu=True)
                                      if self.tee == "tdx"
                                      else self._compute_snp_values(variant, is_gpu=True))

                if not all_values:
                    log.error("No initrd files found in kata RPM")
                    return []

                return all_values

    def _compute_values_for_variant(self, artifacts: dict, initrd_key: str, is_gpu: bool) -> list[ReferenceValue]:
        """Compute measurements for a specific variant (GPU or non-GPU).

        Args:
            artifacts: Dict of artifact paths
            initrd_key: Key in artifacts dict for the initrd to use ("initrd" or "gpu_initrd")
            is_gpu: True for GPU variant, False for regular
        """
        # Create a copy of artifacts with the selected initrd as "initrd"
        variant_artifacts = artifacts.copy()
        variant_artifacts["initrd"] = artifacts[initrd_key]

        if self.tee == "tdx":
            return self._compute_tdx_values(variant_artifacts, is_gpu=is_gpu)
        else:
            return self._compute_snp_values(variant_artifacts, is_gpu=is_gpu)

    def _compute_tdx_values(self, artifact_paths: dict, is_gpu: bool = False) -> list[ReferenceValue]:
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

        cmdlines = self._kernel_cmdlines(is_gpu=is_gpu)
        # TDX UEFI event log measures the cmdline with "initrd=initrd" suffix
        # and null terminator, encoded as UTF-16-LE.
        cmdline_hashes = []
        for cmdline in cmdlines:
            tdx_cmdline = cmdline + " initrd=initrd\x00"
            h = hashlib.sha384(tdx_cmdline.encode("utf-16-le")).hexdigest()
            if h not in cmdline_hashes:
                cmdline_hashes.append(h)
        variant = "GPU " if is_gpu else ""
        source = f"kernel cmdline (--kernel-cmdline --gpu)" if (self.kernel_cmdline and is_gpu) else \
            f"kernel cmdline (--kernel-cmdline)" if self.kernel_cmdline else \
            f"{variant}kata configuration.toml cmdline, nr_cpus=1..{self.max_cpu_count}"
        values.append(ReferenceValue(
            name="tdvfkernelparams",
            values=cmdline_hashes,
            category="executables",
            description="Kernel command line (UTF-16-LE) digest from UEFI event log",
            algorithm="sha384",
            source=source,
        ))

        mr_td = self._compute_mr_td(artifact_paths.get("ovmf_tdx"))
        if mr_td:
            values.append(mr_td)

        rtmrs = self._compute_rtmrs(artifact_paths, is_gpu=is_gpu)
        values.extend(rtmrs)

        return values

    def _compute_snp_values(self, artifact_paths: dict, is_gpu: bool = False) -> list[ReferenceValue]:
        """Compute SNP launch measurement using sev-snp-measure.

        Runs sev-snp-measure once per kernel cmdline variant. The vcpus
        parameter also varies with nr_cpus since kata sets both together.

        Args:
            artifact_paths: Dict of artifact paths
            is_gpu: True for GPU variant, False for regular
        """
        ovmf = artifact_paths.get("ovmf_snp")
        vmlinuz = artifact_paths.get("vmlinuz")
        initrd = artifact_paths.get("initrd")

        if not ovmf:
            log.error("Missing OVMF.amdsev.fd in edk2 RPM. Cannot compute "
                      "SNP launch measurement.")
            return []

        try:
            from sevsnpmeasure.guest import snp_calc_launch_digest
            from sevsnpmeasure.vcpu_types import CPU_SIGS
        except ImportError:
            raise RuntimeError("sev-snp-measure is not installed (pip install sev-snp-measure)")

        cmdlines = self._kernel_cmdlines(is_gpu=is_gpu)
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
            m = ld.hex()
            if m not in measurements:
                measurements.append(m)

        log.info("Computed SNP measurements for %d cmdline variant(s), "
                 "%d unique", len(cmdlines), len(measurements))

        variant = "GPU " if is_gpu else ""
        source_suffix = f"kernel cmdline (--kernel-cmdline --gpu)" if (self.kernel_cmdline and is_gpu) else \
            f"kernel cmdline (--kernel-cmdline)" if self.kernel_cmdline else \
            f"{variant}kata configuration.toml cmdline, nr_cpus=1..{self.max_cpu_count}"

        return [ReferenceValue(
            name="snp_launch_measurement",
            values=measurements,
            category="executables",
            description="SNP launch measurement (OVMF + kernel + initrd + cmdline)",
            algorithm="sha384",
            source=f"sev-snp-measure ({source_suffix})",
        )]

    def _compute_rtmrs(self, artifact_paths: dict, is_gpu: bool = False) -> list[ReferenceValue]:
        """Compute RTMR1 and RTMR2 using tdx-measure --runtime-only.

        Runs tdx-measure once per kernel cmdline variant (one per CPU count,
        or a single user-provided cmdline). Merges unique values.

        Args:
            artifact_paths: Dict of artifact paths
            is_gpu: True for GPU variant, False for regular
        """
        if not shutil.which("tdx-measure"):
            log.warning("tdx-measure not found, skipping RTMR computation")
            return []

        vmlinuz = artifact_paths.get("vmlinuz")
        initrd = artifact_paths.get("initrd")
        if not vmlinuz or not initrd:
            log.warning("Missing kernel or initrd, skipping RTMR computation")
            return []

        cmdlines = self._kernel_cmdlines(is_gpu=is_gpu)
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

        variant = "GPU " if is_gpu else ""
        source_suffix = f"kernel cmdline (--kernel-cmdline --gpu)" if (self.kernel_cmdline and is_gpu) else \
            f"kernel cmdline (--kernel-cmdline)" if self.kernel_cmdline else \
            f"{variant}kata configuration.toml cmdline, nr_cpus=1..{self.max_cpu_count}"

        values = []
        if rtmr1_values:
            values.append(ReferenceValue(
                name="rtmr_1",
                values=rtmr1_values,
                category="executables",
                description="Runtime measurement register 1 (kernel + boot services)",
                algorithm="sha384",
                source=f"tdx-measure --runtime-only ({source_suffix})",
            ))
        if rtmr2_values:
            values.append(ReferenceValue(
                name="rtmr_2",
                values=rtmr2_values,
                category="executables",
                description="Runtime measurement register 2 (kernel cmdline + initrd)",
                algorithm="sha384",
                source=f"tdx-measure --runtime-only ({source_suffix})",
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
