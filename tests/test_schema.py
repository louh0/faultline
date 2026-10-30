from __future__ import annotations

from faultline.schema import infer_json_schema


def test_infer_schema_detects_formats_and_required_fields() -> None:
    sample = {
        "id": "a8098c1a-f86e-11da-bd1a-00112444be1e",
        "created_at": "2026-10-12T09:30:00Z",
        "amount": 1500,
        "active": True,
    }
    schema = infer_json_schema([sample])
    assert schema["type"] == "object"
    assert set(schema["required"]) == {"id", "created_at", "amount", "active"}
    assert schema["properties"]["id"] == {"type": "string", "format": "uuid"}
    assert schema["properties"]["created_at"] == {"type": "string", "format": "date-time"}
    assert schema["properties"]["amount"] == {"type": "integer"}
    assert schema["properties"]["active"] == {"type": "boolean"}


def test_merge_samples_optional_fields_and_nullability() -> None:
    samples = [
        {"id": 1, "nickname": "ace", "score": 10, "extra": "present"},
        {"id": 2, "nickname": None, "score": 12.5},
    ]
    schema = infer_json_schema(samples)
    assert set(schema["required"]) == {"id", "nickname", "score"}
    assert schema["properties"]["nickname"]["type"] == ["string", "null"]
    assert schema["properties"]["score"]["type"] == "number"


def test_infer_schema_merges_array_item_shapes() -> None:
    sample = {
        "events": [
            {"code": "A", "latency": 12},
            {"code": "B", "latency": 15.4, "retry": True},
        ]
    }
    schema = infer_json_schema([sample])
    items_schema = schema["properties"]["events"]["items"]
    assert items_schema["type"] == "object"
    assert set(items_schema["required"]) == {"code", "latency"}
    assert items_schema["properties"]["latency"]["type"] == "number"
    assert items_schema["properties"]["retry"]["type"] == "boolean"
