from cyberguard.core.enums import EventCategory
from cyberguard.ingestion.csv_adapter import CSVAdapter


def test_normalized_csv(tmp_path):
    path = tmp_path / "events.csv"
    path.write_text("timestamp,source,category,event_type,host,message,disk_used_percent,mount\n"
        "2026-10-02T10:00:00Z,monitor,system,disk_usage,db-1,disk high,96,/data\n")
    event = CSVAdapter().parse(path)[0]
    assert event.category == EventCategory.SYSTEM
    assert event.attributes["disk_used_percent"] == 96


def test_common_aliases_and_semicolon_delimiter(tmp_path):
    path = tmp_path / "application-export.csv"
    path.write_text("Date Time;Hostname;Application;Description;HTTP Status\n"
        "2026-10-02 10:00:00;web-1;checkout;request failed;500\n")
    event = CSVAdapter().parse(path)[0]
    assert event.host == "web-1"
    assert event.service == "checkout"
    assert event.event_type == "http_request"
    assert event.attributes["status_code"] == 500


def test_loghub_structured_columns_map_to_error_detection(tmp_path):
    path = tmp_path / "Apache_2k.log_structured.csv"
    path.write_text("LineId,Date,Time,Level,Component,Content,EventId,EventTemplate\n"
        "1,2026-10-02,10:00:00,ERROR,web,Connection refused while opening upstream,E1,Connection refused <*>\n")
    event = CSVAdapter().parse(path)[0]
    assert event.message == "Connection refused while opening upstream"
    assert event.source == "web"
    assert event.attributes["log_level"] == "error"
    assert event.event_type == "E1"


def test_arbitrary_csv_still_produces_useful_record(tmp_path):
    path = tmp_path / "custom.csv"
    path.write_text("custom_a,custom_b\nalpha,beta\n")
    event = CSVAdapter().parse(path)[0]
    assert event.message == "custom_a=alpha; custom_b=beta"
    assert event.attributes["custom_a"] == "alpha"
