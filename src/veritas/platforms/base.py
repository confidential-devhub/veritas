"""Base class for platform-specific reference value extraction."""

from abc import ABC, abstractmethod

from veritas.models import ReferenceValue


class PlatformExtractor(ABC):
    """Base class for platform-specific reference value extraction."""

    @abstractmethod
    def extract(self) -> list[ReferenceValue]:
        """Compute and return all reference values."""

    @abstractmethod
    def compute_initdata(self, initdata_paths: list[str]) -> ReferenceValue:
        """Compute initdata reference value for this platform."""

    @abstractmethod
    def reference_key_names(self) -> set[str]:
        """Return all RVPS key names this extractor can produce."""

    @property
    @abstractmethod
    def platform(self) -> str:
        """Platform name."""

    @property
    @abstractmethod
    def evidence_type(self) -> str:
        """Trustee evidence type."""
