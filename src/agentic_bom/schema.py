"""Schema validation for emitted JSON.

Uses ``jsonschema`` when installed, and always also runs a built-in validator
for the subset of JSON Schema used by our schemas (type, required, properties,
items, enum, const, pattern, minimum, maximum, local $ref), so validation works
with zero runtime dependencies.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from importlib import resources
from typing import Any


class SchemaValidationError(ValueError):
    pass


@lru_cache(maxsize=None)
def load_schema(name: str) -> dict[str, Any]:
    text = resources.files("agentic_bom.schemas").joinpath(f"{name}.schema.json").read_text(encoding="utf-8")
    return json.loads(text)


_TYPES = {"object": dict, "array": list, "string": str, "boolean": bool, "null": type(None)}


def _type_ok(value: Any, t: str) -> bool:
    if t == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if t == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return isinstance(value, _TYPES[t])


def _validate(value: Any, schema: dict[str, Any], root: dict[str, Any], path: str) -> None:
    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/"):
            raise SchemaValidationError(f"unsupported $ref {ref}")
        target: Any = root
        for part in ref[2:].split("/"):
            target = target[part]
        _validate(value, target, root, path)
        return
    if "const" in schema and value != schema["const"]:
        raise SchemaValidationError(f"{path}: expected const {schema['const']!r}, got {value!r}")
    if "enum" in schema and value not in schema["enum"]:
        raise SchemaValidationError(f"{path}: {value!r} not in enum")
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_type_ok(value, t) for t in types):
            raise SchemaValidationError(f"{path}: expected type {types}, got {type(value).__name__}")
    if isinstance(value, str) and "pattern" in schema and not re.search(schema["pattern"], value):
        raise SchemaValidationError(f"{path}: {value!r} does not match {schema['pattern']}")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise SchemaValidationError(f"{path}: {value} < minimum")
        if "maximum" in schema and value > schema["maximum"]:
            raise SchemaValidationError(f"{path}: {value} > maximum")
    if isinstance(value, dict):
        for req in schema.get("required", []):
            if req not in value:
                raise SchemaValidationError(f"{path}: missing required property {req!r}")
        for k, sub in schema.get("properties", {}).items():
            if k in value:
                _validate(value[k], sub, root, f"{path}.{k}")
    if isinstance(value, list) and "items" in schema:
        for i, item in enumerate(value):
            _validate(item, schema["items"], root, f"{path}[{i}]")


def validate(doc: dict[str, Any], name: str) -> None:
    schema = load_schema(name)
    _validate(doc, schema, schema, "$")
    try:
        import jsonschema  # type: ignore
    except ImportError:
        return
    try:
        jsonschema.validate(doc, schema)
    except jsonschema.ValidationError as exc:
        raise SchemaValidationError(f"{'/'.join(map(str, exc.absolute_path))}: {exc.message}") from exc
