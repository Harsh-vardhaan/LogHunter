import copy
import json
import re
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from loghunter.cli import main
from loghunter.reporting import REPORT_SCHEMA_VERSION


class ContractError(AssertionError):
    pass


def validate(instance, schema, root=None, path="$"):
    """Validate the JSON Schema keywords used by the bundled report schema.

    This is a deterministic structural compatibility test, not a runtime JSON
    Schema implementation or dependency.
    """
    root = root or schema
    if "$ref" in schema:
        target = root
        for part in schema["$ref"].removeprefix("#/").split("/"):
            target = target[part]
        return validate(instance, target, root, path)
    if "anyOf" in schema:
        for option in schema["anyOf"]:
            try:
                validate(instance, option, root, path)
                break
            except ContractError:
                continue
        else:
            raise ContractError(f"{path} matched no anyOf option")
    if "const" in schema and instance != schema["const"]:
        raise ContractError(f"{path} did not match const")
    if "enum" in schema and instance not in schema["enum"]:
        raise ContractError(f"{path} was outside enum")
    expected = schema.get("type")
    if expected:
        names = expected if isinstance(expected, list) else [expected]
        checks = {
            "object": lambda value: isinstance(value, dict),
            "array": lambda value: isinstance(value, list),
            "string": lambda value: isinstance(value, str),
            "integer": lambda value: isinstance(value, int) and not isinstance(value, bool),
            "boolean": lambda value: isinstance(value, bool),
            "null": lambda value: value is None,
        }
        if not any(checks[name](instance) for name in names):
            raise ContractError(f"{path} had wrong type")
    if isinstance(instance, dict):
        missing = set(schema.get("required", [])) - set(instance)
        if missing:
            raise ContractError(f"{path} missing {sorted(missing)}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False and set(instance) - set(properties):
            raise ContractError(f"{path} had unexpected properties")
        for key, value in instance.items():
            if key in properties:
                validate(value, properties[key], root, f"{path}.{key}")
    if isinstance(instance, list):
        if len(instance) < schema.get("minItems", 0):
            raise ContractError(f"{path} had too few items")
        if schema.get("uniqueItems") and len({json.dumps(item, sort_keys=True) for item in instance}) != len(instance):
            raise ContractError(f"{path} had duplicate items")
        for index, value in enumerate(instance):
            validate(value, schema.get("items", {}), root, f"{path}[{index}]")
    if isinstance(instance, int) and not isinstance(instance, bool):
        if instance < schema.get("minimum", instance):
            raise ContractError(f"{path} was below minimum")
        if instance > schema.get("maximum", instance):
            raise ContractError(f"{path} exceeded maximum")
    if isinstance(instance, str):
        if len(instance) < schema.get("minLength", 0):
            raise ContractError(f"{path} was too short")
        if "pattern" in schema and not re.fullmatch(schema["pattern"], instance):
            raise ContractError(f"{path} failed pattern")


class ReportSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads(Path("schemas/loghunter-report.schema.json").read_text(encoding="utf-8"))
        output = StringIO()
        with redirect_stdout(output):
            main(["analyze", "samples/auth_sample.log", "--type", "auth", "--format", "json"])
        cls.report = json.loads(output.getvalue())

    def test_schema_dialect_and_version(self):
        self.assertEqual(self.schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertEqual(REPORT_SCHEMA_VERSION, "1.0")

    def test_generated_report_matches_formal_schema(self):
        validate(self.report, self.schema)

    def test_all_severity_values_are_accepted(self):
        for severity in ("INFO", "LOW", "MEDIUM", "HIGH"):
            report = copy.deepcopy(self.report)
            report["findings"][0]["severity"] = severity
            validate(report, self.schema)

    def test_nullable_finding_fields_are_accepted(self):
        report = copy.deepcopy(self.report)
        finding = report["findings"][0]
        for field in ("source_ip", "username", "first_seen", "last_seen"):
            finding[field] = None
        validate(report, self.schema)

    def test_invalid_report_is_rejected(self):
        report = copy.deepcopy(self.report)
        report["summary"]["lines_processed"] = -1
        with self.assertRaises(ContractError):
            validate(report, self.schema)

    def test_phase4_report_without_configuration_remains_compatible(self):
        report = copy.deepcopy(self.report)
        del report["configuration"]
        validate(report, self.schema)
