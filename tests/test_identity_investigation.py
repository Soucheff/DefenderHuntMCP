from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

import server


class Fido2AuthenticationMethod:
    def __init__(self) -> None:
        self.id = "fido-key"
        self.display_name = "Passkey"
        self.created_date_time = None
        self.model = "Security key"
        self.phone_type = None
        self.key_strength = None


@pytest.mark.asyncio
async def test_authentication_posture_degrades_when_registration_report_is_denied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user_request = SimpleNamespace(
        authentication=SimpleNamespace(
            methods=SimpleNamespace(
                get=AsyncMock(
                    return_value=SimpleNamespace(value=[Fido2AuthenticationMethod()])
                )
            )
        )
    )
    registration_request = SimpleNamespace(
        get=AsyncMock(side_effect=PermissionError("denied"))
    )
    client = SimpleNamespace(
        users=SimpleNamespace(by_user_id=lambda _user_id: user_request),
        reports=SimpleNamespace(
            authentication_methods=SimpleNamespace(
                user_registration_details=SimpleNamespace(
                    by_user_registration_details_id=lambda _user_id: registration_request
                )
            )
        ),
    )
    monkeypatch.setattr(server, "get_graph_client", lambda: client)

    result = await server.get_authentication_posture("user-id")

    assert result["status"] == "partial_success"
    assert result["fido2_registered"] is True
    assert result["passkeys_registered"] is True
    assert result["mfa_enabled"] is None
    assert result["errors"][0]["source"] == "user_registration_details"


@pytest.mark.asyncio
async def test_applied_conditional_access_projects_controls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = SimpleNamespace(
        id="policy-id",
        display_name="Require phishing-resistant MFA",
        result="success",
        enforced_grant_controls=["mfa"],
        enforced_session_controls=["signInFrequency"],
    )
    signin = SimpleNamespace(
        id="signin-id",
        user_id="user-id",
        conditional_access_status="success",
        applied_conditional_access_policies=[policy],
    )
    request = SimpleNamespace(get=AsyncMock(return_value=signin))
    client = SimpleNamespace(
        audit_logs=SimpleNamespace(
            sign_ins=SimpleNamespace(by_sign_in_id=lambda _signin_id: request)
        )
    )
    monkeypatch.setattr(server, "get_graph_client", lambda: client)

    result = await server.get_applied_conditional_access("signin-id")

    assert result["policies"][0]["displayName"] == "Require phishing-resistant MFA"
    assert result["controls_applied"] == ["mfa", "signInFrequency"]


@pytest.mark.asyncio
async def test_analyze_signin_risk_has_explainable_score(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def activity(*_args, **_kwargs):
        return {
            "signins": [
                {"result": {"errorCode": 0}},
                {"result": {"errorCode": 50126}},
            ],
            "risk_indicators": [{"signinId": "risky"}],
            "locations": ["BR", "US", "DE"],
        }

    risky_user = SimpleNamespace(
        risk_level="medium",
        risk_state="atRisk",
        risk_detail="unfamiliarFeatures",
        risk_last_updated_date_time=None,
    )
    request = SimpleNamespace(get=AsyncMock(return_value=risky_user))
    client = SimpleNamespace(
        identity_protection=SimpleNamespace(
            risky_users=SimpleNamespace(by_risky_user_id=lambda _user_id: request)
        )
    )
    monkeypatch.setattr(server, "get_signin_activity", activity)
    monkeypatch.setattr(server, "get_graph_client", lambda: client)

    result = await server.analyze_signin_risk("user-id")

    assert result["risk_score"] == 55
    assert result["risk_level"] == "medium"
    assert {item["type"] for item in result["anomalies"]} == {
        "failed_signins",
        "location_variance",
        "risky_signins",
    }


@pytest.mark.asyncio
async def test_next_steps_prioritize_privilege_and_risk() -> None:
    result = await server.recommend_next_investigation_steps(
        {"risk_level": "high", "role": "Global Administrator"}
    )

    assert "get_authentication_posture" in result["recommended_tools"]
    assert "get_privileged_access" in result["recommended_tools"]
    assert "get_pim_activations" in result["recommended_tools"]


def test_identity_key_requires_exactly_one_identifier() -> None:
    assert server._identity_key("user-id", None) == "user-id"
    assert server._identity_key(None, "user@example.com") == "user@example.com"
    with pytest.raises(ValueError, match="exactly one"):
        server._identity_key(None, None)
    with pytest.raises(ValueError, match="exactly one"):
        server._identity_key("user-id", "user@example.com")