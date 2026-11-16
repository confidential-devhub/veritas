# SPDX-License-Identifier: Apache-2.0
#
# Reconstructs the kata-containers 3.x guest kernel command-line assembly.
# Not a line-for-line port of a single upstream file: it mirrors the behaviour
# spread across the kata-containers runtime sources cited per step below.
"""Reconstruct the guest kernel command line from a kata-containers RPM config.

kata-runtime does not use a fixed guest kernel command line: it assembles one
when it launches a pod VM, from several sources, in a fixed order. The TDX
measurement (``tdvfkernelparams`` in the UEFI event log, and the
cmdline-dependent part of ``rtmr_2``) is a digest over that raw string, so a
reference value only matches if the generator reproduces the assembly exactly.

The assembly, for kata-containers 3.x, is (in emission order):

1. fixed x86_64 hypervisor parameters
   (``src/runtime/virtcontainers/qemu_amd64.go``, ``kernelParams``)
2. console parameters (``qemu_arch_base.go``, ``appendConsole``):
   ``console=hvc0 console=hvc1`` for the default virtio serial console,
   ``console=ttyS0`` with ``use_legacy_serial``
3. ``debug`` or ``quiet`` (``[hypervisor.qemu] enable_debug``)
4. systemd parameters for image-based guests (initrd-based guests, which is
   what OSC confidential containers use, get none)
5. ``panic=1`` (``qemu.go``, ``defaultKernelParameters``)
6. ``nr_cpus=N`` (``qemu.go``, the pod's vCPU count)
7. ``selinux=0`` or ``selinux=1`` (``disable_guest_selinux``)
8. ``scsi_mod.scan=none`` when ``block_device_driver`` is ``virtio-scsi``
   (``katautils/config.go``, ``SetKernelParams``)
9. ``agent.*`` parameters from the ``[agent.kata]`` section
   (``kata_agent.go``, ``KataAgentKernelParams``): ``agent.log=debug``,
   ``agent.trace=true``, ``agent.container_pipe_size``,
   ``agent.debug_console`` + ``agent.debug_console_vport``,
   ``agent.cdh_api_timeout``, ``agent.launch_process_timeout``
10. the ``[hypervisor.qemu] kernel_params`` from configuration.toml, last, so
    the user's values take priority (the kernel keeps the last occurrence of
    a repeated parameter)

This module reconstructs that assembly from the ``configuration.toml`` shipped
inside the kata-containers RPM, so reference values are derived from the same
approved configuration the runtime actually uses. The previous approach — a
hardcoded template — drifted from real runtime behaviour: for example the
rhaos 4.22 kata RPM (kata-containers-3.31.0-6.rhaos4.22) sets
``launch_process_timeout = 6``, which kata forwards as
``agent.launch_process_timeout=6``; the template lacked it, so every generated
``tdvfkernelparams``/``rtmr_2`` value mismatched and every real TDX workload
was denied by policy.
"""

from __future__ import annotations

import logging
import tomllib
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

# Fixed x86_64 hypervisor parameters (kata-containers 3.x,
# src/runtime/virtcontainers/qemu_amd64.go, var kernelParams).
HYPERVISOR_BASE_PARAMS = [
    "tsc=reliable",
    "no_timer_check",
    "rcupdate.rcu_expedited=1",
    "i8042.direct=1",
    "i8042.dumbkbd=1",
    "i8042.nopnp=1",
    "i8042.noaux=1",
    "noreplace-smp",
    "reboot=k",
    "cryptomgr.notests",
    "net.ifnames=0",
    "pci=lastbus=0",
]

# Console parameters appended right after the base list
# (qemu_arch_base.go, appendConsole).
VIRTIO_CONSOLE_PARAMS = ["console=hvc0", "console=hvc1"]
LEGACY_SERIAL_CONSOLE_PARAMS = ["console=ttyS0"]

# Fixed vsock port for the agent debug console (kata_agent.go,
# kernelParamDebugConsoleVPortValue).
DEBUG_CONSOLE_VPORT = "1026"


class KataConfigError(RuntimeError):
    """A kata configuration cannot be turned into a guest command line."""


@dataclass(frozen=True)
class KataGuestConfig:
    """The subset of configuration.toml that shapes the guest kernel cmdline.

    Field defaults are the kata runtime defaults
    (src/runtime/pkg/katautils/config-settings.go.in), so a config that does
    not mention a setting behaves like the runtime does.
    """

    kernel_params: str = ""
    hypervisor_debug: bool = False
    legacy_serial: bool = False
    disable_guest_selinux: bool = True
    block_device_driver: str = "virtio-scsi"
    agent_debug: bool = False
    agent_trace: bool = False
    container_pipe_size: int = 0
    debug_console: bool = False
    cdh_api_timeout: int = 0
    launch_process_timeout: int = 0

    @classmethod
    def from_toml(cls, path: str | Path) -> "KataGuestConfig":
        """Parse a kata runtime-class configuration.toml.

        Raises KataConfigError when the file is unreadable, unparseable, or
        describes a guest this module cannot reconstruct a command line for.
        """
        path = Path(path)
        try:
            with open(path, "rb") as f:
                doc = tomllib.load(f)
        except (OSError, tomllib.TOMLDecodeError) as e:
            raise KataConfigError(f"cannot parse kata configuration {path}: {e}") from e

        hyp = doc.get("hypervisor", {}).get("qemu", {})
        if hyp.get("image"):
            raise KataConfigError(
                f"{path}: image-based guests are not supported: kata adds "
                "systemd.* kernel parameters for them that this module does "
                "not reconstruct"
            )
        agent = doc.get("agent", {}).get("kata", {})
        return cls(
            kernel_params=hyp.get("kernel_params", ""),
            hypervisor_debug=hyp.get("enable_debug", False),
            legacy_serial=hyp.get("use_legacy_serial", False),
            disable_guest_selinux=hyp.get("disable_guest_selinux", True),
            block_device_driver=hyp.get("block_device_driver", "virtio-scsi"),
            agent_debug=agent.get("enable_debug", False),
            agent_trace=agent.get("enable_tracing", False),
            container_pipe_size=agent.get("container_pipe_size", 0),
            debug_console=agent.get("debug_console_enabled", False),
            cdh_api_timeout=agent.get("cdh_api_timeout", 0),
            launch_process_timeout=agent.get("launch_process_timeout", 0),
        )


def guest_kernel_cmdline(cfg: KataGuestConfig, nr_cpus: int) -> str:
    """Return the guest kernel command line kata-runtime builds for ``cfg``.

    Mirrors the kata-containers 3.x assembly described in the module docstring
    in the exact emission order — the measured digest is taken over the raw
    string, so ordering matters as much as content.
    """
    if nr_cpus < 1:
        raise ValueError("nr_cpus must be >= 1")

    params = list(HYPERVISOR_BASE_PARAMS)
    params += LEGACY_SERIAL_CONSOLE_PARAMS if cfg.legacy_serial else VIRTIO_CONSOLE_PARAMS
    params.append("debug" if cfg.hypervisor_debug else "quiet")
    params.append("panic=1")
    params.append(f"nr_cpus={nr_cpus}")
    params.append("selinux=0" if cfg.disable_guest_selinux else "selinux=1")
    if cfg.block_device_driver == "virtio-scsi":
        params.append("scsi_mod.scan=none")
    if cfg.agent_debug:
        params.append("agent.log=debug")
    if cfg.agent_trace:
        params.append("agent.trace=true")
    if cfg.container_pipe_size > 0:
        params.append(f"agent.container_pipe_size={cfg.container_pipe_size}")
    if cfg.debug_console:
        params.append("agent.debug_console")
        params.append(f"agent.debug_console_vport={DEBUG_CONSOLE_VPORT}")
    if cfg.cdh_api_timeout > 0:
        params.append(f"agent.cdh_api_timeout={cfg.cdh_api_timeout}")
    if cfg.launch_process_timeout > 0:
        params.append(f"agent.launch_process_timeout={cfg.launch_process_timeout}")
    # The config file's own kernel_params go last: kata re-adds them after its
    # defaults so they take priority (kernel keeps the last occurrence).
    params += cfg.kernel_params.split()
    return " ".join(params)


def cmdline_variants(cfg: KataGuestConfig, max_cpu_count: int) -> list[str]:
    """One command line per vCPU count, kata's ``nr_cpus`` handling."""
    return [guest_kernel_cmdline(cfg, n) for n in range(1, max_cpu_count + 1)]
