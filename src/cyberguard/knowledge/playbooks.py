PLAYBOOKS = {
    "authentication": {
        "title": "Authentication attack triage",
        "steps": [
            "Confirm time window and source identity.",
            "Check whether failures were followed by success.",
            "Review target-account privilege and recent changes.",
            "Contain only after validating business context.",
            "Document evidence and monitor recurrence.",
        ],
    },
    "system": {
        "title": "Infrastructure degradation",
        "steps": [
            "Verify the metric from an independent source.",
            "Identify recent workload and configuration changes.",
            "Assess dependent services and blast radius.",
            "Apply the lowest-risk approved correction.",
            "Validate service-level indicators under normal load.",
        ],
    },
    "application": {
        "title": "Application failure triage",
        "steps": [
            "Group failures by route, exception, and deployment.",
            "Check upstream and database dependency health.",
            "Compare with traffic and release timelines.",
            "Roll back only with evidence and authorization.",
            "Validate critical user journeys and error rate.",
        ],
    },
    "file_integrity": {
        "title": "Sensitive file change",
        "steps": [
            "Preserve file metadata, hash, and process lineage.",
            "Compare with patch and change records.",
            "Inspect related persistence and network activity.",
            "Restore only from a trusted source if unauthorized.",
            "Hunt for the same indicator across the estate.",
        ],
    },
}
