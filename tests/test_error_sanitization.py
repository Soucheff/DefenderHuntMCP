import json

from server import _error_response


def test_error_response_does_not_expose_internal_details(caplog) -> None:
    response = json.loads(
        _error_response(
            "test_operation",
            RuntimeError("secret tenant detail and internal endpoint"),
        )
    )

    assert response == {
        "status": "error",
        "error": "Operation failed",
        "error_code": "UPSTREAM_OR_INTERNAL_ERROR",
    }
    assert "secret tenant detail" not in response["error"]
    assert "secret tenant detail" in caplog.text
