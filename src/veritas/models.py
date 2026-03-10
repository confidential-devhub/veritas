"""Data models for CoCo reference values."""

from dataclasses import dataclass, asdict


CATEGORIES = ("executables", "hardware", "configuration")


@dataclass
class ReferenceValue:
    """A single reference value for Trustee RVPS."""

    name: str
    value: str
    category: str  # executables, hardware, configuration (AR4SI)
    description: str
    algorithm: str  # sha256, sha384
    source: str


def group_by_category(values: list[ReferenceValue]) -> dict:
    """Group values by AR4SI category, dropping the category field."""
    grouped = {cat: [] for cat in CATEGORIES}
    for v in values:
        entry = asdict(v)
        del entry["category"]
        grouped[v.category].append(entry)
    return grouped
