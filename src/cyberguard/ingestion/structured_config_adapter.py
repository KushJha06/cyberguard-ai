import configparser
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import yaml

from cyberguard.core.enums import EventCategory
from cyberguard.core.models import TelemetryEvent

from .base import Adapter

_SECRET_KEY = re.compile(r"password|passwd|secret|token|api[_-]?key|private[_-]?key|client[_-]?secret", re.I)
_ENV_REFERENCE = re.compile(r"^(\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*)$")


class StructuredConfigAdapter(Adapter):
    name = "structured_config"
    extensions = (".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".config", ".xml", ".env", ".properties")

    def supports(self, path: Path) -> bool:
        name = path.name.lower()
        extension_match = super().supports(path) or name == ".env"
        return extension_match and not (path.suffix.lower() in {".conf", ".config"}
            and any(token in name for token in ("ssh", "sshd")))

    def parse(self, path: Path) -> list[TelemetryEvent]:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        if not text.strip():
            raise ValueError("The configuration file is empty")
        suffix = path.suffix.lower()
        try:
            if suffix in {".yaml", ".yml"}:
                config = yaml.safe_load(text) or {}
            elif suffix == ".toml":
                config = tomllib.loads(text)
            elif suffix in {".ini", ".cfg"}:
                config = self._ini(text)
            elif suffix == ".xml":
                config = self._xml(text)
            else:
                config = self._key_values(text)
        except (ValueError, tomllib.TOMLDecodeError, ET.ParseError, yaml.YAMLError) as exc:
            raise ValueError(f"Invalid {suffix or 'configuration'} syntax: {exc}") from exc
        secret_keys = sorted(set(self._secret_keys(config)))
        lowered_name = path.name.lower()
        kind = str(config.get("kind", "")).lower() if isinstance(config, dict) else ""
        event_type = ("docker_compose_snapshot" if "compose" in lowered_name else
            "nginx_config_snapshot" if "nginx" in lowered_name else
            "kubernetes_config_snapshot" if kind in {"pod", "deployment", "daemonset", "statefulset", "job", "cronjob"}
            else "structured_config_snapshot")
        return [TelemetryEvent(source=f"config:{path.name}", category=EventCategory.CONFIGURATION,
            event_type=event_type, host=path.name, message=f"Parsed configuration {path.name}",
            attributes={"filename": path.name, "format": suffix.lstrip("."), "config": config,
                "raw_text": text, "credential_fields_present": secret_keys})]

    @staticmethod
    def _ini(text: str) -> dict[str, Any]:
        parser = configparser.ConfigParser(interpolation=None)
        try:
            parser.read_string(text)
        except configparser.MissingSectionHeaderError:
            return StructuredConfigAdapter._key_values(text)
        return {section: dict(parser.items(section)) for section in parser.sections()}

    @staticmethod
    def _xml(text: str) -> dict[str, Any]:
        root = ET.fromstring(text)
        def convert(node: ET.Element) -> Any:
            children = list(node)
            value: dict[str, Any] = {f"@{key}": item for key, item in node.attrib.items()}
            if children:
                for child in children:
                    converted = convert(child)
                    if child.tag in value:
                        current = value[child.tag]
                        value[child.tag] = current + [converted] if isinstance(current, list) else [current, converted]
                    else:
                        value[child.tag] = converted
            if node.text and node.text.strip():
                value["#text"] = node.text.strip()
            return value or (node.text or "").strip()
        return {root.tag: convert(root)}

    @staticmethod
    def _key_values(text: str) -> dict[str, str]:
        values = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            key, separator, value = line.partition("=")
            if not separator:
                key, separator, value = line.partition(":")
            if separator:
                values[key.strip()] = value.strip().strip('"\'')
        return values

    @classmethod
    def _secret_keys(cls, value: Any, prefix: str = "") -> list[str]:
        found = []
        if isinstance(value, dict):
            for key, item in value.items():
                path = f"{prefix}.{key}".strip(".")
                if _SECRET_KEY.search(str(key)) and item not in (None, "", False) and not _ENV_REFERENCE.match(str(item)):
                    found.append(path)
                found.extend(cls._secret_keys(item, path))
        elif isinstance(value, list):
            for index, item in enumerate(value):
                found.extend(cls._secret_keys(item, f"{prefix}[{index}]"))
        return found
