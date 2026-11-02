from importlib.metadata import entry_points
from typing import Literal

from pydantic import BaseModel

from cyberguard.detection.base import DetectionRule
from cyberguard.detection.registry import RuleRegistry
from cyberguard.ingestion.base import Adapter
from cyberguard.ingestion.registry import AdapterRegistry

PLUGIN_API_VERSION = "1"


class PluginInfo(BaseModel):
    id: str
    kind: Literal["adapter", "detection"]
    distribution: str
    version: str
    source: str = "external"
    status: Literal["loaded", "failed"]
    detail: str | None = None


def _materialize(value):
    return value() if isinstance(value, type) else value


def load_external_plugins(adapters: AdapterRegistry, rules: RuleRegistry,
    enabled: bool = True) -> list[PluginInfo]:
    """Load trusted installed plugins through stable Python entry-point groups."""
    if not enabled:
        return []
    loaded: list[PluginInfo] = []
    groups = (("cyberguard.adapters", "adapter"), ("cyberguard.detections", "detection"))
    for group, kind in groups:
        for point in entry_points(group=group):
            distribution = point.dist.name if point.dist else "unknown"
            version = point.dist.version if point.dist else "unknown"
            try:
                plugin = _materialize(point.load())
                if kind == "adapter":
                    if not isinstance(plugin, Adapter):
                        raise TypeError("Entry point must produce an Adapter")
                    adapters.register(plugin)
                else:
                    if not isinstance(plugin, DetectionRule):
                        raise TypeError("Entry point must produce a DetectionRule")
                    rules.register(plugin)
                loaded.append(PluginInfo(id=point.name, kind=kind, distribution=distribution,
                    version=version, status="loaded"))
            except Exception as exc:
                loaded.append(PluginInfo(id=point.name, kind=kind, distribution=distribution,
                    version=version, status="failed", detail=str(exc)))
    return loaded


def built_in_plugins(adapters: AdapterRegistry, rules: RuleRegistry) -> list[PluginInfo]:
    items = [PluginInfo(id=name, kind="adapter", distribution="cyberguard-ai",
        version=PLUGIN_API_VERSION, source="built-in", status="loaded") for name in adapters.names]
    items.extend(PluginInfo(id=rule_id, kind="detection", distribution="cyberguard-ai",
        version=PLUGIN_API_VERSION, source="built-in", status="loaded") for rule_id in rules.rule_ids)
    return items
