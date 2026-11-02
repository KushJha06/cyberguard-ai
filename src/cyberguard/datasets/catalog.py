from dataclasses import asdict, dataclass


@dataclass(frozen=True, slots=True)
class Dataset:
    id: str
    name: str
    provider: str
    homepage: str
    download_url: str
    license_url: str
    domains: tuple[str, ...]
    formats: tuple[str, ...]
    size_note: str
    license_note: str
    recommended_use: str
    adapter_status: str
    upload_instructions: str
    coverage: tuple[str, ...]

    def as_dict(self) -> dict:
        data = asdict(self)
        for field in ("domains", "formats", "coverage"):
            data[field] = list(data[field])
        return data


DATASETS = (
    Dataset(
        "loghub-2",
        "Loghub 2.0",
        "LogPAI",
        "https://github.com/logpai/loghub-2.0",
        "https://zenodo.org/records/8275861",
        "https://github.com/logpai/loghub-2.0/blob/main/LICENSE",
        ("system", "application", "authentication", "log_parsing"),
        ("LOG", "CSV"),
        "Large collection; download one 2k structured sample first",
        "Research/academic use with repository and paper citation; inspect upstream notice",
        "Real Linux, Apache, OpenSSH, HDFS and distributed-system log parsing",
        "direct",
        "Upload a *_2k.log_structured.csv file or a small raw .log file. Keep each upload under the configured event limit.",
        ("generic_errors", "ssh_authentication", "application_logs"),
    ),
    Dataset(
        "os-metrics",
        "OS-Metrics V1.0",
        "Zenodo community record",
        "https://zenodo.org/records/17981352",
        "https://zenodo.org/records/17981352/files/OSMetrics.zip?download=1",
        "https://zenodo.org/records/17981352",
        ("system", "performance", "anomaly_detection"),
        ("CSV", "ZIP"),
        "715.7 KB; six metric files and three event-log files",
        "Open Zenodo record; verify the rights section and preserve the DOI",
        "CPU, memory and network-response disturbance evaluation",
        "sample_or_transform",
        "Extract the ZIP and upload a CSV slice of no more than 10,000 rows. Rename value columns to memory_used_percent or add CyberGuard canonical columns.",
        ("memory_pressure", "system_metrics", "capacity_research"),
    ),
    Dataset(
        "otrf-security",
        "Security Datasets",
        "Open Threat Research Forum",
        "https://github.com/OTRF/Security-Datasets",
        "https://github.com/OTRF/Security-Datasets/tree/master/datasets",
        "https://github.com/OTRF/Security-Datasets/blob/master/LICENSE",
        ("windows", "powershell", "authentication", "endpoint"),
        ("JSON", "EVTX", "PCAP"),
        "Repository of scenario-specific malicious and benign captures",
        "GPL-3.0 repository; review each scenario's metadata before redistribution",
        "Windows Security, Sysmon and PowerShell detection research",
        "transform",
        "Choose a small JSON Windows-event export. EVTX and PCAP require conversion or a dedicated plugin before upload.",
        ("suspicious_powershell", "windows_authentication", "process_activity"),
    ),
    Dataset(
        "lanl-unified",
        "LANL Unified Host and Network",
        "Los Alamos National Laboratory",
        "https://csr.lanl.gov/data/2017/",
        "https://csr.lanl.gov/data/2017/",
        "https://csr.lanl.gov/data/2017/",
        ("authentication", "process", "network", "host"),
        ("JSONL", "CSV"),
        "Enterprise scale; approximately 90 days—use a bounded slice",
        "Provider publishes terms on the official dataset page; retain provenance",
        "Authentication, process and host/network correlation",
        "transform",
        "Select one source and time window, map fields to CyberGuard JSONL, and upload a slice below 10,000 events.",
        ("ssh_authentication", "process_activity", "cross_host_correlation"),
    ),
    Dataset(
        "cic-ids-2017",
        "CIC-IDS2017",
        "Canadian Institute for Cybersecurity",
        "https://www.unb.ca/cic/datasets/ids-2017.html",
        "https://www.unb.ca/cic/datasets/ids-2017.html",
        "https://www.unb.ca/cic/datasets/ids-2017.html",
        ("network", "intrusion_detection", "brute_force"),
        ("PCAP", "CSV"),
        "Multi-day packet captures and generated flow CSV files",
        "Review and accept official provider terms before downloading",
        "Network attacks, brute force and future flow-based rules",
        "adapter_needed",
        "Use a labeled flow CSV only after mapping CIC columns; raw PCAP is not currently interpreted.",
        ("network_brute_force", "dos_research", "flow_adapter"),
    ),
    Dataset(
        "unsw-nb15",
        "UNSW-NB15",
        "UNSW Canberra",
        "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
        "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
        "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
        ("network", "intrusion_detection"),
        ("PCAP", "Bro", "Argus", "CSV"),
        "2,540,044 records; official training and test subsets are available",
        "Research dataset; verify the current terms on the official page",
        "Labeled network classification and future scan/exfiltration rules",
        "adapter_needed",
        "Upload only a mapped CSV subset. Bro, Argus and PCAP need dedicated adapters.",
        ("network_intrusion", "port_scan_research", "exfiltration_research"),
    ),
    Dataset(
        "ton-iot",
        "ToN-IoT",
        "UNSW Canberra",
        "https://research.unsw.edu.au/projects/toniot-datasets",
        "https://research.unsw.edu.au/projects/toniot-datasets",
        "https://research.unsw.edu.au/projects/toniot-datasets",
        ("network", "windows", "linux", "iot"),
        ("CSV", "LOG"),
        "Heterogeneous Windows, Linux, network and IoT telemetry",
        "Verify current provider terms for each collection",
        "Cross-source evaluation and adapter development",
        "transform",
        "Choose one CSV source, retain its label column, and map timestamp, host, service, message and relevant metrics.",
        ("cross_source", "system_activity", "network_intrusion"),
    ),
    Dataset(
        "splunk-attack-data",
        "Attack Data",
        "Splunk Security Research",
        "https://github.com/splunk/attack_data",
        "https://github.com/splunk/attack_data/tree/master/datasets",
        "https://github.com/splunk/attack_data/blob/master/LICENSE",
        ("windows", "linux", "cloud", "endpoint"),
        ("LOG", "JSON", "XML"),
        "Scenario-based datasets; sizes vary by attack simulation",
        "Apache-2.0 repository; inspect dataset-specific metadata",
        "Detection engineering and ATT&CK-aligned scenario evaluation",
        "transform",
        "Download one scenario's raw event export. Convert XML/EVTX captures to JSON or CSV before upload.",
        ("powershell", "process_activity", "authentication"),
    ),
)


def list_datasets() -> list[dict]:
    return [dataset.as_dict() for dataset in DATASETS]


def get_dataset(dataset_id: str) -> Dataset | None:
    return next((item for item in DATASETS if item.id == dataset_id), None)
