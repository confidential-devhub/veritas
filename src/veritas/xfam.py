"""XFAM (Extended Features Allowed Mask) computation from feature names.

Bit definitions from Intel SDM Vol. 1, Chapter 13 (XSAVE) and
Intel TDX Module specification.
"""

import struct

# XCR0 bits (processor extended state)
XFAM_FEATURES = {
    "x87":      0,
    "sse":      1,
    "avx":      2,
    "mpx_bndregs": 3,
    "mpx_bndcsr":  4,
    "avx512":   (5, 6, 7),  # opmask + ZMM_Hi256 + Hi16_ZMM
    "pkru":     9,
    # IA32_XSS bits
    "amx":      (17, 18),   # TILECFG + TILEDATA
}


def compute_xfam(features):
    """Compute XFAM bitmask from feature names, return as little-endian hex.

    Args:
        features: list of feature names (e.g. ["x87", "sse", "avx"])

    Returns:
        Little-endian hex string (e.g. "e702060000000000")
    """
    mask = 0
    for name in features:
        name = name.strip().lower()
        if name not in XFAM_FEATURES:
            valid = ", ".join(sorted(XFAM_FEATURES))
            raise ValueError(f"Unknown XFAM feature: {name}. Valid features: {valid}")
        bits = XFAM_FEATURES[name]
        if isinstance(bits, tuple):
            for b in bits:
                mask |= 1 << b
        else:
            mask |= 1 << bits
    return struct.pack("<Q", mask).hex()
