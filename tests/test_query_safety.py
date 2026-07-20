import pytest

from query_safety import quote_kql_string, quote_odata_string
from server import _build_risky_signins_filter


def test_quote_kql_string_prevents_literal_breakout() -> None:
    value = 'device"; union AlertInfo | where true; //'

    assert quote_kql_string(value) == '"device\\"; union AlertInfo | where true; //"'


def test_quote_odata_string_escapes_apostrophes() -> None:
    value = "alice' or riskLevel eq 'high"

    assert quote_odata_string(value) == "'alice'' or riskLevel eq ''high'"


@pytest.mark.parametrize("value", ["", "   ", "line\nbreak"])
def test_query_literals_reject_empty_or_control_values(value: str) -> None:
    with pytest.raises(ValueError):
        quote_kql_string(value)


def test_risky_signin_filter_applies_state_and_escapes_upn() -> None:
    result = _build_risky_signins_filter(
        "2026-07-01T00:00:00Z",
        "alice'o@example.com",
        "high",
        "atRisk",
    )

    assert "userPrincipalName eq 'alice''o@example.com'" in result
    assert "riskLevelDuringSignIn eq 'high'" in result
    assert "riskState eq 'atRisk'" in result
