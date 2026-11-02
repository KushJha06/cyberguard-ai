from cyberguard.core.models import Incident


def export_incident(incident: Incident) -> str:
    return incident.model_dump_json(indent=2)
