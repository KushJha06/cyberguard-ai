from .application.database_pool import DatabasePoolRule
from .application.generic_error import GenericErrorRule
from .application.http_error_spike import HTTPErrorSpikeRule
from .configuration.config_risks import ConfigurationRiskRule
from .configuration.insecure_ssh import InsecureSSHRule
from .file_integrity.sensitive_file_change import SensitiveFileChangeRule
from .registry import RuleRegistry
from .security.brute_force import SSHBruteForceRule
from .security.suspicious_powershell import SuspiciousPowerShellRule
from .system.capacity_forecast import CapacityForecastRule
from .system.disk_full import DiskFullRule
from .system.memory_pressure import MemoryPressureRule
from .system.service_down import ServiceDownRule


def default_registry() -> RuleRegistry:
    registry = RuleRegistry()
    rules = (
        SSHBruteForceRule(), SuspiciousPowerShellRule(), DiskFullRule(), CapacityForecastRule(),
        MemoryPressureRule(), ServiceDownRule(), HTTPErrorSpikeRule(), DatabasePoolRule(), GenericErrorRule(),
        InsecureSSHRule(), ConfigurationRiskRule(), SensitiveFileChangeRule(),
    )
    for rule in rules:
        registry.register(rule)
    return registry


__all__ = ["RuleRegistry", "default_registry"]
