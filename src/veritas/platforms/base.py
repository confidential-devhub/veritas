"""Base class for platform-specific reference value extraction."""

from abc import ABC, abstractmethod

from veritas.models import ReferenceValue


class PlatformExtractor(ABC):
    """Base class for platform-specific reference value extraction."""

    @abstractmethod
    def extract(self) -> list[ReferenceValue]:
        """Compute and return all reference values."""

    @abstractmethod
    def compute_initdata(self, initdata_path: str) -> ReferenceValue:
        """Compute initdata reference value for this platform."""

    @property
    @abstractmethod
    def platform(self) -> str:
        """Platform name."""

    @property
    @abstractmethod
    def evidence_type(self) -> str:
        """Trustee evidence type."""
