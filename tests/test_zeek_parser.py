"""Parser tests against captured Zeek JSON and TSV fixtures."""

from pathlib import Path

import pytest

from src.realtime.zeek_parser import ZeekLogParser, log_type_for_path

FIXTURES = Path(__file__).parent / "fixtures" / "zeek_realtime"


@pytest.fixture()
def parser() -> ZeekLogParser:
    return ZeekLogParser()


def test_json_conn_record_is_normalized(parser: ZeekLogParser) -> None:
    line = (FIXTURES / "conn.log").read_text(encoding="utf-8").splitlines()[0]
    record = parser.parse_line("conn.log", line)
    assert record is not None

    event = parser.normalize(record, "conn", "sensor-test", "conn.log", 0)
    assert event is not None
    assert event.src_ip == "10.0.0.5"
    assert event.dst_ip == "93.184.216.34"
    assert event.dst_port == 443
    assert event.proto == "tcp"
    assert event.service == "ssl"
    assert event.conn_state == "SF"
    assert event.orig_bytes == 512
    assert event.resp_pkts == 9
    assert event.ts == pytest.approx(1700000000.123456)


def test_event_uid_is_stable_and_source_scoped(parser: ZeekLogParser) -> None:
    lines = (FIXTURES / "conn.log").read_text(encoding="utf-8").splitlines()
    record = parser.parse_line("conn.log", lines[1])
    other_record = parser.parse_line("conn.log", lines[0])

    first = parser.normalize(record, "conn", "sensor-test", "conn.log", 100)
    replayed = parser.normalize(record, "conn", "sensor-test", "conn.log", 900)
    other_sensor = parser.normalize(record, "conn", "sensor-b", "conn.log", 100)
    different_flow = parser.normalize(other_record, "conn", "sensor-test", "conn.log", 100)

    assert first is not None and replayed is not None
    assert first.event_uid == replayed.event_uid  # Zeek uid, not the file offset
    assert first.event_uid.endswith("C5d6e7f8")
    assert first.event_uid != other_sensor.event_uid
    assert first.event_uid != different_flow.event_uid


def test_tsv_log_uses_header_fields(parser: ZeekLogParser) -> None:
    lines = (FIXTURES / "conn_tsv.log").read_text(encoding="utf-8").splitlines()
    records = []
    for line in lines:
        parsed = parser.parse_line("conn_tsv.log", line)
        if parsed is not None:
            records.append(parsed)

    assert len(records) == 2
    event = parser.normalize(records[0], "conn", "sensor-test", "conn_tsv.log", 0)
    assert event is not None
    assert event.src_ip == "192.168.1.10"
    assert event.dst_port == 53
    assert event.proto == "udp"
    assert event.orig_bytes == 64


def test_tsv_without_header_is_ignored(parser: ZeekLogParser) -> None:
    assert parser.parse_line("no_header.log", "1700000100.0\tuid\t1.2.3.4") is None


def test_malformed_json_returns_none(parser: ZeekLogParser) -> None:
    assert parser.parse_line("conn.log", '{"ts": 1.0, "uid": ') is None
    assert parser.parse_line("conn.log", "") is None


def test_record_without_timestamp_is_rejected(parser: ZeekLogParser) -> None:
    record = parser.parse_line("conn.log", '{"uid": "C1", "id.orig_h": "10.0.0.1"}')
    assert parser.normalize(record, "conn", "sensor-test", "conn.log") is None


def test_dns_event_keeps_query_in_raw(parser: ZeekLogParser) -> None:
    line = (FIXTURES / "dns.log").read_text(encoding="utf-8").strip()
    record = parser.parse_line("dns.log", line)
    event = parser.normalize(record, "dns", "sensor-test", "dns.log", 0)

    assert event is not None
    assert event.log_type == "dns"
    assert event.src_ip == "10.0.0.7"
    assert event.raw["query"].startswith("aGVsbG8")


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("conn.log", "conn"),
        ("conn.2023-11-14-22-00-00.log.gz", "conn"),
        ("dns.log", "dns"),
        ("http.log", "http"),
    ],
)
def test_log_type_for_path(path: str, expected: str) -> None:
    assert log_type_for_path(path) == expected
