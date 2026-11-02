from .archive_adapter import ArchiveAdapter
from .config_file_adapter import SSHConfigAdapter
from .csv_adapter import CSVAdapter
from .json_adapter import JSONAdapter
from .registry import AdapterRegistry
from .structured_config_adapter import StructuredConfigAdapter
from .universal_adapter import UniversalTextAdapter


def default_registry() -> AdapterRegistry:
    registry = AdapterRegistry()
    for adapter in (
        CSVAdapter(),
        JSONAdapter(),
        SSHConfigAdapter(),
        StructuredConfigAdapter(),
        ArchiveAdapter(),
        UniversalTextAdapter(),
    ):
        registry.register(adapter)
    return registry


__all__ = [
    "AdapterRegistry",
    "ArchiveAdapter",
    "CSVAdapter",
    "JSONAdapter",
    "SSHConfigAdapter",
    "StructuredConfigAdapter",
    "UniversalTextAdapter",
    "default_registry",
]
