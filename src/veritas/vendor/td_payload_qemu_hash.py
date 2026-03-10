#!/usr/bin/env python3
# Copyright (c) 2026 Red Hat, Inc.
# Copyright (c) 2026 Alibaba Cloud
# Copyright (c) 2025 Phala Network
# Copyright (c) 2025 Tinfoil Inc
#
# SPDX-License-Identifier: Apache-2.0
#
# PE Authenticode hash from:
#   https://github.com/confidential-containers/td-shim
#   td-shim-tools/src/bin/td-payload-reference-calculator/td_payload_qemu_hash.py
#
# QEMU kernel patching ported from:
#   https://github.com/virtee/tdx-measure
#   src/kernel.rs (patch_kernel function)
#
# Calculates tdvfkernel reference value for TDX direct boot. QEMU patches
# the kernel setup_header before OVMF measures it, so we must apply the
# same patches before computing the PE Authenticode hash. Once RHEL ships
# a QEMU that skips patching for TDX guests (already fixed upstream),
# this patching logic can be removed.

import hashlib
import struct
from pathlib import Path

IMAGE_PE_OFFSET = 0x003C
PE_SIGNATURE_SIZE = 4
IMAGE_BEGIN_ADDR = 0x0000
IMAGE_PROTOCOL_ADDR = 0x0206

# QEMU's ACPI data size for TDX guests (from tdx-measure).
ACPI_DATA_SIZE = 0x28000


def _read_u16(buf, offset):
    return struct.unpack_from("<H", buf, offset)[0]


def _read_u32(buf, offset):
    return struct.unpack_from("<I", buf, offset)[0]


def _write_u32(buf, offset, value):
    struct.pack_into("<I", buf, offset, value)


def patch_kernel(buf, initrd_size, mem_size):
    """Patch kernel setup_header the way QEMU does for direct boot.

    Ported from tdx-measure (virtee/tdx-measure, src/kernel.rs).
    """
    protocol = _read_u16(buf, 0x206)

    if protocol < 0x200 or (buf[0x211] & 0x01) == 0:
        real_addr = 0x90000
        cmdline_addr = 0x9A000
    else:
        real_addr = 0x10000
        cmdline_addr = 0x20000

    if protocol >= 0x200:
        buf[0x210] = 0xB0  # type_of_loader = Qemu v0

    if protocol >= 0x201:
        buf[0x211] |= 0x80  # loadflags |= CAN_USE_HEAP
        heap_end_ptr = cmdline_addr - real_addr - 0x200
        _write_u32(buf, 0x224, heap_end_ptr)

    if protocol >= 0x202:
        _write_u32(buf, 0x228, cmdline_addr)
    else:
        struct.pack_into("<H", buf, 0x20, 0xA33F)
        offset = (cmdline_addr - real_addr) & 0xFFFF
        struct.pack_into("<H", buf, 0x22, offset)

    if initrd_size > 0:
        if protocol < 0x200:
            raise ValueError("Kernel too old for ramdisk")

        if protocol >= 0x20C:
            xlf = _read_u16(buf, 0x236)
            initrd_max = 0xFFFFFFFF if (xlf & 0x40) != 0 else 0x37FFFFFF
        elif protocol >= 0x203:
            initrd_max = _read_u32(buf, 0x22C)
            if initrd_max == 0:
                initrd_max = 0x37FFFFFF
        else:
            initrd_max = 0x37FFFFFF

        if mem_size < 0xB0000000:
            lowmem = 0xB0000000
        else:
            lowmem = 0x80000000

        below_4g = min(mem_size, lowmem)

        if initrd_max >= below_4g - ACPI_DATA_SIZE:
            initrd_max = below_4g - ACPI_DATA_SIZE - 1

        if initrd_size >= initrd_max:
            raise ValueError("initrd is too large")

        initrd_addr = (initrd_max - initrd_size) & ~0xFFF
        _write_u32(buf, 0x218, initrd_addr)
        _write_u32(buf, 0x21C, initrd_size)


def _get_image_regions(buf):
    """Get PE image regions for Authenticode hashing."""
    regions_base = []
    regions_size = []

    size_of_coff_file_header = 20

    coff_file_header_offset = _read_u32(buf, IMAGE_PE_OFFSET) + PE_SIGNATURE_SIZE

    number_of_pecoff_entry = _read_u16(buf, coff_file_header_offset + 2)

    size_of_optional_header = _read_u16(buf, coff_file_header_offset + 16)

    optional_header_addr = coff_file_header_offset + size_of_coff_file_header

    optional_checksum_offset = 0x0040
    optional_cert_table_offset = 0x0090

    size_of_headers = _read_u32(
        buf, optional_header_addr + 0x003C
    )

    # Region 1: from file begin to CheckSum
    regions_base.append(IMAGE_BEGIN_ADDR)
    regions_size.append(
        optional_header_addr + optional_checksum_offset - IMAGE_BEGIN_ADDR
    )

    # Region 2: from CheckSum end to certificate table entry
    regions_base.append(optional_header_addr + optional_checksum_offset + 4)
    regions_size.append(
        optional_cert_table_offset - (optional_checksum_offset + 4)
    )

    # Region 3: from cert table end to header end
    regions_base.append(optional_header_addr + optional_cert_table_offset + 8)
    regions_size.append(
        size_of_headers
        - (optional_header_addr + optional_cert_table_offset + 8)
    )

    # PE sections
    p = (
        coff_file_header_offset
        + size_of_coff_file_header
        + size_of_optional_header
    )
    for _ in range(number_of_pecoff_entry):
        p += 16
        size = _read_u32(buf, p)
        p += 4
        base = _read_u32(buf, p)
        regions_base.append(base)
        regions_size.append(size)
        p += 20

    return len(regions_base), regions_base, regions_size


def compute_kernel_hash(
    kernel_path: str,
    initrd_size: int = 0,
    mem_size: int = 0x80000000,
) -> str:
    """Compute tdvfkernel hash from a vmlinuz binary.

    Applies QEMU's direct boot patches to the kernel setup_header,
    then computes the PE Authenticode hash (SHA-384) matching what
    OVMF measures in the UEFI event log.

    Args:
        kernel_path: Path to vmlinuz binary.
        initrd_size: Size of the initrd file in bytes.
        mem_size: VM memory size in bytes (default: 2 GB, kata default).
    """
    path = Path(kernel_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    buf = bytearray(path.read_bytes())

    if len(buf) < 0x1000:
        raise ValueError("Kernel image too short")

    protocol = _read_u16(buf, IMAGE_PROTOCOL_ADDR)
    if protocol < 0x206:
        raise ValueError("Protocol version should be 2.06+")

    patch_kernel(buf, initrd_size, mem_size)

    hasher = hashlib.sha384()
    num_regions, regions_base, regions_size = _get_image_regions(buf)

    for index in range(num_regions):
        region_data = buf[
            regions_base[index] : regions_base[index] + regions_size[index]
        ]
        hasher.update(region_data)

    return hasher.hexdigest()
