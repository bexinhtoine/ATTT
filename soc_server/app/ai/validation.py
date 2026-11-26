"""Validate the JSON subset used by SOC schemas, including local/mock providers."""
import math


def validate_json(value, schema, path="result"):
    kind = schema.get("type")
    checks = {"object": lambda v: isinstance(v, dict), "array": lambda v: isinstance(v, list),
              "string": lambda v: isinstance(v, str), "integer": lambda v: type(v) is int,
              "number": lambda v: type(v) in (int, float) and math.isfinite(v),
              "boolean": lambda v: type(v) is bool}
    if kind in checks and not checks[kind](value):
        raise ValueError("%s phải có kiểu %s" % (path, kind))
    if "enum" in schema and value not in schema["enum"]:
        raise ValueError("%s ngoài tập giá trị cho phép" % path)
    if kind == "object":
        for key in schema.get("required", []):
            if key not in value:
                raise ValueError("%s thiếu %s" % (path, key))
        for key, item in value.items():
            if key in schema.get("properties", {}):
                validate_json(item, schema["properties"][key], path + "." + key)
            elif schema.get("additionalProperties") is False:
                raise ValueError("%s có trường không hỗ trợ: %s" % (path, key))
    if kind == "array":
        for index, item in enumerate(value):
            validate_json(item, schema.get("items", {}), "%s[%d]" % (path, index))
    if kind in ("number", "integer"):
        if "minimum" in schema and value < schema["minimum"]:
            raise ValueError("%s dưới giới hạn" % path)
        if "maximum" in schema and value > schema["maximum"]:
            raise ValueError("%s vượt giới hạn" % path)
