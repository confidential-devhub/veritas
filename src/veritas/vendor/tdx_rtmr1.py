#!/usr/bin/env python3
# Copyright (c) 2026 Red Hat, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# RTMR1 event-log model for TDX direct kernel boot.
#
# Ported from: https://github.com/virtee/tdx-measure
# Path: src/kernel.rs (measure_rtmr1_direct), src/util.rs (measure_log)
#
# RTMR1 chains the PE/COFF measurement of the guest kernel with a fixed
# set of firmware boot events. QEMU used to patch the bzImage setup
# header before OVMF measured the kernel; QEMU shipped in RHEL 10 and
# later skips that patch for TDX guests, so those guests measure the
# pristine kernel. The tdx-measure CLI only models the patched variant,
# so this port also supports the unpatched one (patched=False).
# Reference values should be emitted for both.

import hashlib

from veritas.vendor.td_payload_qemu_hash import compute_kernel_hash

# Firmware events extended into RTMR1 around the kernel measurement
# during OVMF direct boot (fixed across OVMF builds).
_FW_EVENTS = (
    b"Calling EFI Application from Boot Option",
    b"\x00\x00\x00\x00",  # Separator
    b"Exit Boot Services Invocation",
    b"Exit Boot Services Returned with Success",
)


def rtmr1_direct(kernel_path: str, initrd_size: int = 0,
                 mem_size: int = 0xB0000000, patched: bool = True) -> str:
    """Compute RTMR1 for TDX direct kernel boot.

    Mirrors tdx-measure's --runtime-only behaviour. initrd_size and
    mem_size only matter for the patched variant (they feed QEMU's
    initrd placement in the setup header); the unpatched variant is a
    pure function of the kernel binary.

    Args:
        kernel_path: Path to the vmlinuz binary.
        initrd_size: Size of the initrd file in bytes (patched only).
        mem_size: VM memory size in bytes (patched only).
        patched: Apply QEMU's direct boot patches to the kernel before
            hashing, as older QEMU releases do for TDX guests.

    Returns:
        The hex-encoded RTMR1 value.
    """
    kernel_hash = bytes.fromhex(compute_kernel_hash(
        kernel_path, initrd_size=initrd_size, mem_size=mem_size,
        patched=patched))
    rtmr = b"\x00" * 48
    events = [kernel_hash] + [hashlib.sha384(e).digest() for e in _FW_EVENTS]
    for event in events:
        rtmr = hashlib.sha384(rtmr + event).digest()
    return rtmr.hex()
