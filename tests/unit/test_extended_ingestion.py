import zipfile

from cyberguard.core.models import TelemetryEvent
from cyberguard.detection.application.generic_error import GenericErrorRule
from cyberguard.detection.configuration.config_risks import ConfigurationRiskRule
from cyberguard.ingestion import default_registry
from cyberguard.ingestion.archive_adapter import ArchiveAdapter
from cyberguard.ingestion.structured_config_adapter import StructuredConfigAdapter


def test_docker_compose_risks(tmp_path):
    path = tmp_path / "docker-compose.yml"
    path.write_text("""services:
  app:
    image: example/app:latest
    privileged: true
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      API_TOKEN: plaintext-demo-value
""")
    event = StructuredConfigAdapter().parse(path)[0]
    finding = ConfigurationRiskRule().evaluate([event])[0]
    assert finding.severity == "high"
    assert "privileged" in finding.summary
    assert event.attributes["credential_fields_present"] == ["services.app.environment.API_TOKEN"]


def test_generic_error_log_creates_triage_finding():
    event = TelemetryEvent(
        source="application.log", message="Fatal exception while starting application"
    )
    assert GenericErrorRule().evaluate([event])[0].rule_id == "CG-APP-003"


def test_config_registry_routes_ssh_nginx_and_dotenv(tmp_path):
    ssh = tmp_path / "sshd_config.conf"
    nginx = tmp_path / "nginx.conf"
    env = tmp_path / ".env"
    for path in (ssh, nginx, env):
        path.write_text("debug=true\n")
    registry = default_registry()
    assert registry.detect(ssh).name == "ssh_config"
    assert registry.detect(nginx).name == "structured_config"
    assert registry.detect(env).name == "structured_config"


def test_kubernetes_security_context_risks(tmp_path):
    path = tmp_path / "deployment.yaml"
    path.write_text(
        "kind: Deployment\nspec:\n  template:\n    spec:\n      hostNetwork: true\n      containers:\n        - name: api\n          image: api:latest\n          securityContext:\n            privileged: true\n"
    )
    event = StructuredConfigAdapter().parse(path)[0]
    finding = ConfigurationRiskRule().evaluate([event])[0]
    assert event.event_type == "kubernetes_config_snapshot"
    assert "host networking" in finding.summary
    assert "runs privileged" in finding.summary


def test_safe_archive_bundle(tmp_path):
    archive = tmp_path / "telemetry.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("metrics.csv", "host,message,disk_usage,mount\ndb-1,disk high,96,/data\n")
        bundle.writestr("app.env", "DEBUG=true\nPASSWORD=plaintext-demo\n")
    events = ArchiveAdapter().parse(archive)
    assert len(events) == 2
    assert {event.event_type for event in events} == {"disk_usage", "structured_config_snapshot"}
