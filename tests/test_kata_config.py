# SPDX-License-Identifier: Apache-2.0
"""Regression guard for the guest kernel cmdline reconstruction.

veritas.vendor.kata_config reconstructs, by hand, the command line
kata-runtime assembles at VM launch. That model can drift from kata's real
behaviour as kata evolves, and a drifted cmdline silently produces wrong
tdvfkernelparams / rtmr_2 measurements. These tests pin the reconstruction to
values measured by real Intel TDX hardware, so any such drift fails here
instead of in production.

The anchors come from a bare-metal OpenShift 4.22.19 cluster running
kata-containers 3.31.0-6.rhaos4.22: the guest cmdline kata-runtime assembled
was captured from the qemu ``-append`` of a live TDX sandbox, and the
tdvfkernelparams digest was read from the TDX quote the workload presented to
Trustee. The configs below are the field-level equivalents of that RPM's
kata-tdx and kata-tdx-nvidia-gpu configuration.toml; the cmdline assertions
fail if those fields are transcribed wrong, so the anchor cannot pass by
accident.
"""

import hashlib

from veritas.vendor.kata_config import (
    KataGuestConfig,
    cmdline_variants,
    guest_kernel_cmdline,
)

# kata-tdx (default runtime class), rhaos 4.22: hypervisor debug on,
# agent debug on, launch_process_timeout=6, and the config's own trailing
# kernel_params.
RHAOS_4_22_TDX_CONFIG = KataGuestConfig(
    kernel_params="cgroup_no_v1=all systemd.unified_cgroup_hierarchy=1",
    hypervisor_debug=True,
    agent_debug=True,
    launch_process_timeout=6,
)

# What kata-runtime 3.31.0 built for a 1-vCPU pod (captured from the qemu
# -append line of a real TDX sandbox).
RHAOS_4_22_TDX_CMDLINE_1CPU = (
    "tsc=reliable no_timer_check rcupdate.rcu_expedited=1 "
    "i8042.direct=1 i8042.dumbkbd=1 i8042.nopnp=1 i8042.noaux=1 "
    "noreplace-smp reboot=k cryptomgr.notests net.ifnames=0 "
    "pci=lastbus=0 console=hvc0 console=hvc1 debug panic=1 "
    "nr_cpus=1 selinux=0 scsi_mod.scan=none agent.log=debug "
    "agent.launch_process_timeout=6 "
    "cgroup_no_v1=all systemd.unified_cgroup_hierarchy=1"
)

# sha384 over UTF-16-LE of "<cmdline> initrd=initrd\0" — the TDX UEFI event
# log measurement of the kernel command line, as measured by real TDX
# hardware. The pre-fix hardcoded template (missing
# agent.launch_process_timeout=6) produced a different digest, so every real
# workload was denied by the Restricted policy.
RHAOS_4_22_TDX_KERNELPARAMS_DIGEST = (
    "6ef06ed2beffd85f705e1cd008ece8d03f53072dd5404f183040104f8a0ecd6e0"
    "e156a67ca6dd0cef28f7bcc95c8c4bc"
)

# kata-tdx-nvidia-gpu, rhaos 4.22: launch_process_timeout=15 and GPU PCI
# kernel_params.
RHAOS_4_22_GPU_CONFIG = KataGuestConfig(
    kernel_params="cgroup_no_v1=all pci=realloc pci=nocrs pci=assign-busses nvrc.smi.srs=1",
    hypervisor_debug=True,
    agent_debug=True,
    launch_process_timeout=15,
)

RHAOS_4_22_GPU_CMDLINE_1CPU = (
    "tsc=reliable no_timer_check rcupdate.rcu_expedited=1 "
    "i8042.direct=1 i8042.dumbkbd=1 i8042.nopnp=1 i8042.noaux=1 "
    "noreplace-smp reboot=k cryptomgr.notests net.ifnames=0 "
    "pci=lastbus=0 console=hvc0 console=hvc1 debug panic=1 "
    "nr_cpus=1 selinux=0 scsi_mod.scan=none agent.log=debug "
    "agent.launch_process_timeout=15 "
    "cgroup_no_v1=all pci=realloc pci=nocrs pci=assign-busses nvrc.smi.srs=1"
)


def _tdx_kernelparams_digest(cmdline: str) -> str:
    """Digest the TDX event-log record for the kernel command line."""
    return hashlib.sha384(
        (cmdline + " initrd=initrd\x00").encode("utf-16-le")
    ).hexdigest()


def test_tdx_cmdline_matches_what_kata_runtime_built():
    assert guest_kernel_cmdline(RHAOS_4_22_TDX_CONFIG, 1) == RHAOS_4_22_TDX_CMDLINE_1CPU


def test_tdx_digest_matches_hardware_measurement():
    """The digest real TDX hardware measured must be derivable, no TOFU."""
    digest = _tdx_kernelparams_digest(guest_kernel_cmdline(RHAOS_4_22_TDX_CONFIG, 1))
    assert digest == RHAOS_4_22_TDX_KERNELPARAMS_DIGEST


def test_stale_assembly_is_detected():
    """A reconstruction that drops agent.launch_process_timeout=6 (the exact
    pre-fix bug, and the shape any future kata drift would take) must NOT
    reproduce the measured digest — otherwise this guard would be useless."""
    stale = RHAOS_4_22_TDX_CMDLINE_1CPU.replace(" agent.launch_process_timeout=6", "")
    assert _tdx_kernelparams_digest(stale) != RHAOS_4_22_TDX_KERNELPARAMS_DIGEST


def test_gpu_cmdline_matches_kata_runtime_construction():
    assert guest_kernel_cmdline(RHAOS_4_22_GPU_CONFIG, 1) == RHAOS_4_22_GPU_CMDLINE_1CPU


def test_nr_cpus_variants_differ_only_in_cpu_count():
    variants = cmdline_variants(RHAOS_4_22_TDX_CONFIG, 3)
    assert len(variants) == 3
    normalized = {
        v.replace(f"nr_cpus={i + 1}", "nr_cpus=N") for i, v in enumerate(variants)
    }
    assert normalized == {RHAOS_4_22_TDX_CMDLINE_1CPU.replace("nr_cpus=1", "nr_cpus=N")}
