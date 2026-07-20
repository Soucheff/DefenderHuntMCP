from types import SimpleNamespace

from server import (
    _audit_target_matches,
    _build_alert_statistics_query,
    _build_data_exfiltration_queries,
    _conditional_access_state_matches,
)


def test_alert_statistics_count_distinct_alert_ids() -> None:
    query = _build_alert_statistics_query("1d")

    assert "TotalAlerts = dcount(AlertId)" in query
    assert 'HighSeverity = dcountif(AlertId, Severity == "High")' in query
    assert "UniqueDevices = dcount(DeviceId)" in query
    assert "TotalAlerts = count()" not in query


def test_conditional_access_state_uses_exact_match() -> None:
    assert _conditional_access_state_matches("enabled", "enabled")
    assert not _conditional_access_state_matches(
        "enabledForReportingButNotEnforced",
        "enabled",
    )
    assert _conditional_access_state_matches("enabledForReportingButNotEnforced", "all")


def test_audit_target_filter_rejects_missing_targets() -> None:
    assert not _audit_target_matches(None, "admin")
    assert _audit_target_matches(None, None)
    assert _audit_target_matches([SimpleNamespace(display_name="Admin Role")], "admin")


def test_exfiltration_queries_use_documented_network_columns() -> None:
    queries = _build_data_exfiltration_queries(7, "all")
    network_queries = queries["large_transfers"] + queries["cloud_storage"]

    assert "SentBytes" not in network_queries
    assert " by DeviceName, AccountName," not in network_queries
    assert "InitiatingProcessAccountName" in network_queries
    assert "Connections=count()" in network_queries
