import re
from typing import Any

from cyberguard.core.enums import EventCategory, Severity
from cyberguard.core.models import Evidence, Finding, TelemetryEvent
from cyberguard.detection.base import DetectionRule


class ConfigurationRiskRule(DetectionRule):
    rule_id = "CG-CFG-002"
    title = "Risky configuration settings"

    def evaluate(self, events: list[TelemetryEvent]) -> list[Finding]:
        findings = []
        for event in events:
            if event.category != EventCategory.CONFIGURATION or event.event_type == "ssh_config_snapshot":
                continue
            config = event.attributes.get("config", {})
            text = str(event.attributes.get("raw_text", ""))
            risks = self._generic_risks(config)
            if event.event_type == "docker_compose_snapshot":
                risks.extend(self._docker_risks(config))
            if event.event_type == "kubernetes_config_snapshot":
                risks.extend(self._kubernetes_risks(config))
            if "nginx" in str(event.attributes.get("filename", "")).lower() or event.event_type == "nginx_config_snapshot":
                risks.extend(self._nginx_risks(text))
            credential_fields = event.attributes.get("credential_fields_present", [])
            risks.extend(f"Potential plaintext secret in {key}" for key in credential_fields)
            risks = list(dict.fromkeys(risks))
            if not risks:
                continue
            severe = any(token in risk.lower() for risk in risks for token in ("privileged", "docker socket", "plaintext secret", "tls disabled"))
            findings.append(Finding(rule_id=self.rule_id, title=self.title,
                category=EventCategory.CONFIGURATION, severity=Severity.HIGH if severe else Severity.MEDIUM,
                confidence=.84, summary="; ".join(risks[:6]) + ".",
                root_cause="The supplied configuration contains settings that can increase exposure, privilege or credential risk.",
                evidence=[Evidence(event_id=event.id, summary=risk,
                    details={"filename": event.attributes.get("filename")}) for risk in risks[:10]],
                analyst_checks=["Confirm effective runtime configuration and whether each setting is required by an approved design.",
                    "Check deployment overrides, included files, environment injection and secret-management controls."],
                remediation=["Move secrets to an approved secret store and apply least privilege, secure transport and explicit versioning through change control."],
                validation=["Run the component's native configuration validator and repeat security checks after deployment."],
                limitations=["Static configuration analysis cannot see all runtime overrides or business requirements."],
                correlation_key=f"config-risk:{event.host or event.attributes.get('filename', 'unknown')}"))
        return findings

    @staticmethod
    def _walk(value: Any, prefix: str = ""):
        if isinstance(value, dict):
            for key, item in value.items():
                path = f"{prefix}.{key}".strip(".")
                yield path.lower(), item
                yield from ConfigurationRiskRule._walk(item, path)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                yield from ConfigurationRiskRule._walk(item, f"{prefix}[{index}]")

    @classmethod
    def _generic_risks(cls, config: Any) -> list[str]:
        risks = []
        for path, value in cls._walk(config):
            normalized = str(value).lower()
            if path.endswith(("debug", "debug_mode")) and normalized in {"true", "1", "yes", "on"}:
                risks.append(f"Debug mode enabled at {path}")
            if any(path.endswith(key) for key in ("verify_ssl", "ssl_verify", "tls_verify")) and normalized in {"false", "0", "no", "off"}:
                risks.append(f"TLS certificate verification disabled at {path}")
            if path.endswith(("allow_anonymous", "anonymous_access")) and normalized in {"true", "1", "yes"}:
                risks.append(f"Anonymous access enabled at {path}")
        return risks

    @staticmethod
    def _docker_risks(config: Any) -> list[str]:
        risks = []
        services = config.get("services", {}) if isinstance(config, dict) else {}
        if not isinstance(services, dict):
            return risks
        for name, service in services.items():
            if not isinstance(service, dict):
                continue
            if service.get("privileged") is True:
                risks.append(f"Docker service {name} runs privileged")
            if str(service.get("network_mode", "")).lower() == "host":
                risks.append(f"Docker service {name} uses host networking")
            if str(service.get("user", "")).lower() in {"0", "root", "0:0"}:
                risks.append(f"Docker service {name} explicitly runs as root")
            if any("/var/run/docker.sock" in str(volume) for volume in service.get("volumes", []) or []):
                risks.append(f"Docker service {name} mounts the Docker socket")
            image = str(service.get("image", ""))
            if image and (":" not in image.rsplit("/", 1)[-1] or image.endswith(":latest")):
                risks.append(f"Docker service {name} uses an unpinned image")
        return risks

    @staticmethod
    def _kubernetes_risks(config: Any) -> list[str]:
        risks = []
        if not isinstance(config, dict):
            return risks
        kind = str(config.get("kind", "resource"))
        spec = config.get("spec", {})
        if isinstance(spec, dict) and isinstance(spec.get("template"), dict):
            spec = spec["template"].get("spec", {})
        if not isinstance(spec, dict):
            return risks
        for key, label in (("hostNetwork", "host networking"), ("hostPID", "host PID namespace"),
            ("hostIPC", "host IPC namespace")):
            if spec.get(key) is True:
                risks.append(f"Kubernetes {kind} uses {label}")
        volumes = spec.get("volumes", []) or []
        if any(isinstance(volume, dict) and "hostPath" in volume for volume in volumes):
            risks.append(f"Kubernetes {kind} mounts a hostPath volume")
        for container in (spec.get("containers", []) or []) + (spec.get("initContainers", []) or []):
            if not isinstance(container, dict):
                continue
            name = str(container.get("name", "unnamed"))
            security = container.get("securityContext", {}) or {}
            if isinstance(security, dict):
                if security.get("privileged") is True:
                    risks.append(f"Kubernetes container {name} runs privileged")
                if security.get("allowPrivilegeEscalation") is True:
                    risks.append(f"Kubernetes container {name} permits privilege escalation")
                if security.get("runAsNonRoot") is False:
                    risks.append(f"Kubernetes container {name} explicitly permits root execution")
            image = str(container.get("image", ""))
            if image and (":" not in image.rsplit("/", 1)[-1] or image.endswith(":latest")):
                risks.append(f"Kubernetes container {name} uses an unpinned image")
        return risks

    @staticmethod
    def _nginx_risks(text: str) -> list[str]:
        risks = []
        if re.search(r"(?im)^\s*server_tokens\s+on\s*;", text):
            risks.append("Nginx server tokens are enabled")
        if re.search(r"(?im)^\s*autoindex\s+on\s*;", text):
            risks.append("Nginx directory autoindex is enabled")
        if re.search(r"(?im)^\s*ssl_protocols\s+[^;]*(TLSv1(?:\.0)?|SSLv[23])", text):
            risks.append("Nginx permits a legacy TLS/SSL protocol")
        if re.search(r"(?im)add_header\s+Access-Control-Allow-Origin\s+[\"']?\*", text):
            risks.append("Nginx permits wildcard cross-origin access")
        return risks
