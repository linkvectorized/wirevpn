#!/usr/bin/env python3
"""Small JSON Schema 2020-12 subset validator for the closed harness schemas."""

import json
import re


class SchemaValidationError(ValueError):
    def __init__(self, errors):
        self.errors = tuple(errors)
        super().__init__("; ".join(self.errors[:8]))


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _type_matches(value, expected):
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    return False


def validate(instance, schema, root=None, path="$", errors=None, depth=0):
    errors = [] if errors is None else errors
    if isinstance(schema, bool):
        if not schema:
            errors.append("%s: rejected by false schema" % path)
        return errors
    root = schema if root is None else root
    if depth > 80 or len(errors) >= 100:
        errors.append("%s: schema evaluation limit exceeded" % path)
        return errors
    if "$ref" in schema:
        reference = schema["$ref"]
        if not reference.startswith("#/"):
            errors.append("%s: non-local $ref is denied" % path)
            return errors
        target = root
        try:
            for part in reference[2:].split("/"):
                target = target[part.replace("~1", "/").replace("~0", "~")]
        except (KeyError, TypeError):
            errors.append("%s: unresolved $ref %s" % (path, reference))
            return errors
        return validate(instance, target, root, path, errors, depth + 1)
    if "type" in schema:
        expected = schema["type"]
        alternatives = expected if isinstance(expected, list) else [expected]
        if not any(_type_matches(instance, item) for item in alternatives):
            errors.append("%s: expected type %s" % (path, expected))
            return errors
    if "const" in schema and instance != schema["const"]:
        errors.append("%s: does not equal required constant" % path)
    if "enum" in schema and instance not in schema["enum"]:
        errors.append("%s: is not an allowed value" % path)
    if "allOf" in schema:
        for subschema in schema["allOf"]:
            validate(instance, subschema, root, path, errors, depth + 1)
    for keyword, required_matches in (("anyOf", 1), ("oneOf", 1)):
        if keyword in schema:
            matches = 0
            for subschema in schema[keyword]:
                if not validate(instance, subschema, root, path, [], depth + 1):
                    matches += 1
            if (keyword == "anyOf" and matches < required_matches) or (keyword == "oneOf" and matches != 1):
                errors.append("%s: %s matched %d alternatives" % (path, keyword, matches))
    if isinstance(instance, dict):
        for key in schema.get("required", []):
            if key not in instance:
                errors.append("%s: missing required property %s" % (path, key))
        properties = schema.get("properties", {})
        for key, value in instance.items():
            if key in properties:
                validate(value, properties[key], root, "%s.%s" % (path, key), errors, depth + 1)
            elif schema.get("additionalProperties") is False:
                errors.append("%s: unknown property %s" % (path, key))
            elif isinstance(schema.get("additionalProperties"), dict):
                validate(value, schema["additionalProperties"], root, "%s.%s" % (path, key), errors, depth + 1)
        if "minProperties" in schema and len(instance) < schema["minProperties"]:
            errors.append("%s: too few properties" % path)
        if "maxProperties" in schema and len(instance) > schema["maxProperties"]:
            errors.append("%s: too many properties" % path)
    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append("%s: too few items" % path)
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            errors.append("%s: too many items" % path)
        if schema.get("uniqueItems"):
            encoded = [_canonical(item) for item in instance]
            if len(set(encoded)) != len(encoded):
                errors.append("%s: duplicate array items" % path)
        if "items" in schema:
            for index, value in enumerate(instance):
                validate(value, schema["items"], root, "%s[%d]" % (path, index), errors, depth + 1)
        if "contains" in schema:
            if not any(not validate(value, schema["contains"], root, path, [], depth + 1) for value in instance):
                errors.append("%s: no item satisfies contains" % path)
    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append("%s: string is too short" % path)
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            errors.append("%s: string is too long" % path)
        if "pattern" in schema and re.search(schema["pattern"], instance) is None:
            errors.append("%s: string does not match required pattern" % path)
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append("%s: below minimum" % path)
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append("%s: above maximum" % path)
    return errors


def require_valid(instance, schema):
    errors = validate(instance, schema)
    if errors:
        raise SchemaValidationError(errors)
