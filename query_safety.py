import json

MAX_QUERY_VALUE_LENGTH = 2048


def _validate_query_value(value: str) -> str:
    if not value or not value.strip():
        raise ValueError("Query value cannot be empty")
    if len(value) > MAX_QUERY_VALUE_LENGTH:
        raise ValueError(f"Query value cannot exceed {MAX_QUERY_VALUE_LENGTH} characters")
    if any(ord(character) < 32 for character in value):
        raise ValueError("Query value cannot contain control characters")
    return value


def quote_kql_string(value: str) -> str:
    """Return a validated KQL string literal using JSON-compatible escaping."""
    return json.dumps(_validate_query_value(value), ensure_ascii=True)


def quote_odata_string(value: str) -> str:
    """Return a validated OData string literal with apostrophes escaped."""
    return "'" + _validate_query_value(value).replace("'", "''") + "'"
