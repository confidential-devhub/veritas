"""Platform extractors registry."""

from veritas.platforms.azure import AzureExtractor
from veritas.platforms.baremetal import BaremetalExtractor

EXTRACTORS = {
    "azure": AzureExtractor,
    "baremetal": BaremetalExtractor,
}
