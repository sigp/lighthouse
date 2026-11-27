#!/usr/bin/env python3
"""Validate captured real OTLP round trips against the published common measurement schema.

Requires jsonschema (test tooling only). Run the Rust tests with
PQ_MEASUREMENT_HOOK_CAPTURE=/tmp/pq-hooks.json, then pass that file here.
"""
import argparse
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("captures", nargs="+", type=Path)
    args = parser.parse_args()
    schema = json.loads((Path(__file__).parent / "fixtures/schema.json").read_text())
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    for path in args.captures:
        records = json.loads(path.read_text())
        for index, record in enumerate(records):
            errors = list(validator.iter_errors(record))
            if errors:
                raise SystemExit(f"{path}:{index}: {record['event_name']}: " + "; ".join(e.message for e in errors))
        print(f"{path}: {len(records)} canonical records valid")


if __name__ == "__main__":
    main()
