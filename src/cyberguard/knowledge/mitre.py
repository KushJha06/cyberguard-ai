TECHNIQUES = {
    "T1110.001": {"name": "Password Guessing", "tactic": "Credential Access", "guidance": "Review authentication source, targeted identities, and any subsequent successful sessions."},
    "T1021.004": {"name": "SSH", "tactic": "Lateral Movement", "guidance": "Validate remote-access authorization and hardening of effective SSH settings."},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution", "guidance": "Inspect script blocks, command lineage, signer, user context, and network behavior."},
    "T1565.001": {"name": "Stored Data Manipulation", "tactic": "Impact", "guidance": "Establish whether the file change was authorized and recover from a trusted source if not."},
}


def lookup(technique_id: str) -> dict[str, str] | None:
    return TECHNIQUES.get(technique_id)
