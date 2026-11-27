#!/usr/bin/env python3
"""Account for every case in an explicitly selected PQ minimal reference artifact."""
import argparse
import collections
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, required=True, help="Root containing tests/minimal/pq")
    parser.add_argument("--reports", type=Path, nargs="+", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.fixtures / "tests/minimal/pq"
    inventory = {str(path.parent.relative_to(root)) for path in root.rglob("manifest.yaml")}
    if not inventory:
        parser.error("No fixture manifests found")
    observations = collections.defaultdict(list)
    for directory in args.reports:
        for path in sorted(directory.rglob("*.json")):
            report = json.loads(path.read_text())
            for case in report.get("cases", []):
                observations[case["case"]].append({**case, "report": str(path)})
    unexpected = set(observations) - inventory
    if unexpected:
        parser.error(f"Reports contain cases outside the selected artifact: {sorted(unexpected)[:5]}")
    cases = []
    counts = collections.Counter()
    by_runner = collections.defaultdict(collections.Counter)
    nonfailures = {"passed", "skipped_bls", "skipped_known_failure"}
    for name in sorted(inventory):
        seen = observations[name]
        outcomes = {case["outcome"] for case in seen}
        if not seen:
            outcome = "not_run"
        elif outcomes - nonfailures:
            outcome = "unsupported" if all(x.startswith("unsupported") for x in outcomes) else "failed"
        elif "passed" in outcomes:
            outcome = "passed"
        else:
            outcome = "skipped"
        cases.append({"case": name, "outcome": outcome, "observations": seen})
        counts[outcome] += 1
        by_runner[name.split("/")[0]][outcome] += 1
    result = {"fixture_root": str(root), "total": len(inventory), "counts": dict(counts),
              "by_runner": {name: dict(count) for name, count in sorted(by_runner.items())}, "cases": cases}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key != "cases"}, indent=2))


if __name__ == "__main__":
    main()
