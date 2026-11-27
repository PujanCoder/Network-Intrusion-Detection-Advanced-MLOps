"""Feature-schema tests: one implementation for training and inference."""

import math

import pytest

from src.realtime.features import (
    FEATURE_ORDER,
    features_from_zeek,
    port_class_code,
    vector,
)
from src.realtime.zeek_parser import ZeekLogParser
from tests.conftest import conn_event


def test_feature_order_has_no_raw_port() -> None:
    assert "dst_port_class" in FEATURE_ORDER
    assert "dst_port" not in FEATURE_ORDER


@pytest.mark.parametrize(
    ("port", "expected"),
    [
        (443, 1.0),
        (8080, 1.0),
        (21, 2.0),
        (445, 2.0),
        (22, 3.0),
        (3389, 3.0),
        (25, 4.0),
        (3306, 5.0),
        (53, 6.0),
        (123, 6.0),
        (512, 7.0),
        (49152, 8.0),
    ],
)
def test_port_class_mapping(port: int, expected: float) -> None:
    assert port_class_code(port) == expected


def test_port_class_handles_missing() -> None:
    assert port_class_code(None) is None
    assert port_class_code("") is None


def test_zeek_features_match_schema_and_derived_fields() -> None:
    features = features_from_zeek(conn_event(dst_port=443, orig_bytes=512, resp_bytes=4821))
    assert features is not None
    assert set(features) == set(FEATURE_ORDER)
    assert features["dst_port_class"] == 1.0
    assert features["orig_bytes"] == 512
    assert features["bytes_ratio"] == pytest.approx(512 / 4821, rel=1e-6)
    assert len(vector(features)) == len(FEATURE_ORDER)


def test_zero_duration_flow_yields_missing_rates() -> None:
    features = features_from_zeek(conn_event(duration=0.0))
    assert features is not None
    assert features["flow_bytes_per_s"] is None
    assert math.isnan(vector(features)[FEATURE_ORDER.index("flow_bytes_per_s")])


def test_non_conn_event_has_no_flow_vector() -> None:
    parser = ZeekLogParser()
    line = (
        '{"ts": 1700000200.5, "uid": "Cdns001", "id.orig_h": "10.0.0.7", "id.orig_p": 53535,'
        ' "id.resp_h": "10.0.0.1", "id.resp_p": 53, "proto": "udp", "query": "example.com"}'
    )
    record = parser.parse_line("dns.log", line)
    event = parser.normalize(record, "dns", "sensor-test", "dns.log", 0)
    assert features_from_zeek(event) is None
