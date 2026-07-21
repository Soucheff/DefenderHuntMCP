def test_alerts_v2_builder_matches_locked_msgraph_sdk() -> None:
    from msgraph.generated.security.alerts_v2.alerts_v2_request_builder import (
        Alerts_v2RequestBuilder,
    )

    assert Alerts_v2RequestBuilder.Alerts_v2RequestBuilderGetQueryParameters
    assert Alerts_v2RequestBuilder.Alerts_v2RequestBuilderGetRequestConfiguration