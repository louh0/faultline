from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

_ISO_DATETIME_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?$"
)
_UUID_STR_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


@dataclass
class SchemaNode:
    types: set[str] = field(default_factory=set)
    nullable: bool = False
    formats: set[str] = field(default_factory=set)
    properties: dict[str, SchemaNode] = field(default_factory=dict)
    required_keys: set[str] = field(default_factory=set)
    observed_object_count: int = 0
    item_schema: SchemaNode | None = None

    def to_json_schema(self) -> dict[str, Any]:
        active_types = sorted(self.types)
        if self.nullable and "null" not in active_types:
            active_types.append("null")

        schema: dict[str, Any] = {}
        if len(active_types) == 1:
            schema["type"] = active_types[0]
        elif active_types:
            schema["type"] = active_types

        if self.formats and "string" in self.types and len(self.formats) == 1:
            schema["format"] = next(iter(self.formats))

        if "object" in self.types:
            schema["properties"] = {
                k: v.to_json_schema() for k, v in sorted(self.properties.items())
            }
            schema["required"] = sorted(self.required_keys)

        if "array" in self.types and self.item_schema is not None:
            schema["items"] = self.item_schema.to_json_schema()

        return schema


def _detect_string_format(value: str) -> str | None:
    if _UUID_STR_RE.match(value):
        return "uuid"
    if _ISO_DATETIME_RE.match(value):
        return "date-time"
    return None


def infer_schema_node(value: Any) -> SchemaNode:
    node = SchemaNode()
    if value is None:
        node.types.add("null")
        node.nullable = True
        return node

    if isinstance(value, bool):
        node.types.add("boolean")
        return node

    if isinstance(value, int):
        node.types.add("integer")
        return node

    if isinstance(value, float):
        node.types.add("number")
        return node

    if isinstance(value, str):
        node.types.add("string")
        fmt = _detect_string_format(value)
        if fmt:
            node.formats.add(fmt)
        return node

    if isinstance(value, list):
        node.types.add("array")
        merged_items: SchemaNode | None = None
        for item in value:
            item_node = infer_schema_node(item)
            merged_items = (
                item_node if merged_items is None else merge_schema_nodes(merged_items, item_node)
            )
        node.item_schema = merged_items
        return node

    if isinstance(value, dict):
        node.types.add("object")
        node.observed_object_count = 1
        for k, v in value.items():
            key_str = str(k)
            node.properties[key_str] = infer_schema_node(v)
            node.required_keys.add(key_str)
        return node

    node.types.add("string")
    return node


def merge_schema_nodes(left: SchemaNode, right: SchemaNode) -> SchemaNode:
    merged_types = set(left.types) | set(right.types)
    if "integer" in merged_types and "number" in merged_types:
        merged_types.discard("integer")

    nullable = left.nullable or right.nullable or ("null" in merged_types)
    non_null_types = {t for t in merged_types if t != "null"}
    if non_null_types and nullable:
        merged_types = non_null_types

    merged = SchemaNode(
        types=merged_types if merged_types else {"null"},
        nullable=nullable,
        formats=set(left.formats) & set(right.formats)
        if (left.formats and right.formats)
        else (set(left.formats) | set(right.formats)),
    )

    if "object" in merged.types:
        merged.observed_object_count = left.observed_object_count + right.observed_object_count
        all_keys = set(left.properties.keys()) | set(right.properties.keys())

        if left.observed_object_count > 0 and right.observed_object_count > 0:
            merged.required_keys = set(left.required_keys) & set(right.required_keys)
        elif left.observed_object_count > 0:
            merged.required_keys = set(left.required_keys)
        else:
            merged.required_keys = set(right.required_keys)

        for key in all_keys:
            if key in left.properties and key in right.properties:
                merged.properties[key] = merge_schema_nodes(
                    left.properties[key], right.properties[key]
                )
            elif key in left.properties:
                merged.properties[key] = left.properties[key]
            else:
                merged.properties[key] = right.properties[key]

    if "array" in merged.types:
        if left.item_schema is not None and right.item_schema is not None:
            merged.item_schema = merge_schema_nodes(left.item_schema, right.item_schema)
        else:
            merged.item_schema = left.item_schema or right.item_schema

    return merged


def infer_json_schema(samples: list[Any]) -> dict[str, Any]:
    if not samples:
        return {}
    acc = infer_schema_node(samples[0])
    for sample in samples[1:]:
        acc = merge_schema_nodes(acc, infer_schema_node(sample))
    result = acc.to_json_schema()
    result["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    return result
