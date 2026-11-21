#!/usr/bin/env python3
"""Render Lighthouse PQ timing exports as normalized three-slot timelines."""

import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass, field
import io
import json
from pathlib import Path
import re
import statistics

NS_PER_SECOND = 1_000_000_000
ARRIVALS = {"individual": "Individual attestations received", "aggregate": "Network aggregates received"}
COMMITTEE = "Committee proof backend finished"


def offset_seconds(event, run):
    """Preserve late arrivals across slot boundaries."""
    timing = run["timing"]
    reference_start = (
        run["genesis_time"] * NS_PER_SECOND
        + (event["reference_slot"] - run["genesis_slot"]) * timing["slot_ns"]
    )
    return (event["wall_ns"] - reference_start) / NS_PER_SECOND


def read_records(directory, run):
    import zstandard

    # Use finalized, listed chunks so a live recorder can also be reported.
    for entry in run["chunks"]:
        path = directory / entry["name"]
        if path.parent != directory or not path.name.endswith(".jsonl.zst"):
            raise ValueError(f"Invalid chunk path {path}")
        with path.open("rb") as file:
            reader = zstandard.ZstdDecompressor().stream_reader(file)
            with io.TextIOWrapper(reader, encoding="utf-8") as stream:
                for line in stream:
                    yield json.loads(line)


def percentile(values, probability):
    position = (len(values) - 1) * probability
    lower = int(position)
    upper = min(lower + 1, len(values) - 1)
    return values[lower] + (values[upper] - values[lower]) * (position - lower)


def box(values):
    values = sorted(values)
    return {
        "whislo": percentile(values, 0.05), "q1": percentile(values, 0.25),
        "med": percentile(values, 0.5), "q3": percentile(values, 0.75),
        "whishi": percentile(values, 0.95), "mean": statistics.fmean(values), "fliers": [],
    }


@dataclass
class Cohort:
    scenario: str
    committee_count: int | None = None
    active_validators: int | None = None
    # Samples are stored as near-reference offsets, independent of operation durations.
    rows: dict = field(default_factory=lambda: defaultdict(list))
    ready: dict = field(default_factory=lambda: defaultdict(list))
    rounds: dict = field(default_factory=lambda: defaultdict(set))
    finished: set = field(default_factory=set)
    eligible: set = field(default_factory=set)
    outcomes: Counter = field(default_factory=Counter)
    snapshots: list = field(default_factory=list)

    @property
    def label(self):
        geometry = (
            f"{self.committee_count} committees"
            if self.committee_count is not None else "committee count unknown"
        )
        if self.active_validators is not None:
            geometry += f", {self.active_validators:,} active validators"
        return f"{self.scenario.replace('_', ' ')} · {geometry}"


def cohort_key(event):
    return event["scenario"], event.get("committee_count"), event.get("active_validators")


def proof_row(event):
    if event["work"] == "committee":
        return COMMITTEE
    if event["work"] == "fallback":
        return "Proposal fallback backend finished"
    return f"Merge R{event['round']} backend finished"


def summarize(run, records):
    cohorts = {}
    planned = {}
    observed_slots = {}
    jobs = {}
    skipped = Counter()
    arrivals = {}
    validated = set()
    duplicate_receipts = Counter()
    missed_anchors = 0
    clock_steps = 0
    for event in records:
        kind = event["kind"]
        if kind == "message_received" and event.get("source") == "network":
            key = event["message_kind"], event["message_id"]
            previous = arrivals.get(key)
            if previous is not None:
                duplicate_receipts[key] += 1
            observed = event["mono_ns"]
            if previous is None or observed < previous[0]:
                arrivals[key] = observed, event["reference_slot"], offset_seconds(event, run)
        elif kind == "validated" and event["outcome"] != "deferred":
            validated.add((event["message_kind"], event["message_id"]))
        elif kind == "experiment_gap":
            missed_anchors += event["count"]
        elif kind == "clock_discontinuity":
            clock_steps += 1
        elif kind == "experiment_planned":
            if event["outcome"] != "planned":
                skipped[(event["scenario"], event["outcome"])] += 1
                continue
            key = cohort_key(event)
            cohort = cohorts.setdefault(key, Cohort(*key))
            planned[event["experiment_id"]] = key
            observed_slots[event["reference_slot"]] = key
            cohort.outcomes["planned"] += 1
            if event.get("target_slot") is not None:
                cohort.eligible.add(event["sequence_id"])
        elif kind in ("proof_started", "proof_finished", "candidate_ready", "job_outcome", "proposal_snapshot", "input_cutoff"):
            # Multi-producer record ordering can differ from clock and sequence ordering.
            jobs.setdefault(kind, []).append(event)

    for kind, events in jobs.items():
        for event in events:
            key = planned.get(event.get("experiment_id"))
            if key is None:
                if event.get("origin") != "production":
                    skipped[("unknown", "missing_plan")] += 1
                    continue
                key = ("production", None, None)
            cohort = cohorts.setdefault(key, Cohort(*key))
            sequence = event.get("sequence_id")
            if kind == "proof_started":
                if event.get("work") == "initial":
                    cohort.eligible.add(sequence)
                continue
            if kind == "proof_finished":
                if event["outcome"] == "success":
                    row = proof_row(event)
                    cohort.rows[row].append(offset_seconds(event, run))
                    if event["work"] in ("initial", "improvement"):
                        cohort.rounds[event["round"]].add(sequence)
                    if event.get("late"):
                        cohort.outcomes["late backend finish"] += 1
                else:
                    cohort.outcomes["backend failure"] += 1
            elif kind == "candidate_ready":
                cohort.ready[proof_row(event)].append(offset_seconds(event, run))
            elif kind == "proposal_snapshot":
                cohort.finished.add(sequence)
                cohort.snapshots.append(offset_seconds(event, run))
                cohort.outcomes[f"snapshot {event['outcome']}"] += 1
                if cohort.scenario == "production":
                    cohort.eligible.add(sequence)
            elif kind == "job_outcome":
                cohort.outcomes[event["outcome"]] += 1
            elif kind == "input_cutoff" and event.get("foreign_overrun"):
                cohort.outcomes["foreign overrun at cutoff"] += 1

    network = Cohort("all network receipts")
    for message, (_, slot, offset) in arrivals.items():
        row = ARRIVALS[message[0]]
        network.rows[row].append(offset)
        if message not in validated:
            network.outcomes["receipts without terminal validation"] += 1
        if duplicates := duplicate_receipts[message]:
            network.outcomes["duplicate deliveries"] += duplicates
        if key := observed_slots.get(slot):
            cohorts[key].rows[row].append(offset)
            if message not in validated:
                cohorts[key].outcomes["receipts without terminal validation"] += 1
            if duplicates:
                cohorts[key].outcomes["duplicate deliveries"] += duplicates
    if missed_anchors:
        network.outcomes["missed cadence anchors"] += missed_anchors
    if not cohorts or network.rows:
        cohorts[("all network receipts", None, None)] = network
    for key, cohort in cohorts.items():
        if clock_steps:
            cohort.outcomes["clock discontinuities"] += clock_steps
        for (scenario, reason), count in skipped.items():
            if scenario == cohort.scenario or cohort is network:
                cohort.outcomes[f"skipped {reason}"] += count
        if (incomplete := len(cohort.eligible - cohort.finished)):
            cohort.outcomes["sequences without a snapshot"] += incomplete
    return cohorts


def render(run, cohort, output, *, show_mean):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.lines import Line2D

    timing = run["timing"]
    slot, att, collect, aggregate, initial = [
        timing[name] / NS_PER_SECOND for name in (
            "slot_ns", "attestation_ns", "committee_collection_ns", "aggregate_ns", "initial_merge_ns",
        )
    ]
    end = 3 * slot
    max_round = max(4, *cohort.rounds.keys()) if cohort.rounds else 4
    rows = [ARRIVALS["individual"], COMMITTEE, ARRIVALS["aggregate"]]
    rows.extend(f"Merge R{round_number} backend finished" for round_number in range(1, max_round + 1))
    fallback = "Proposal fallback backend finished"
    if cohort.rows[fallback]:
        rows.append(fallback)

    fig, ax = plt.subplots(figsize=(14, 0.57 * len(rows) + 4.1), dpi=170)
    fig.subplots_adjust(left=0.31, right=0.96, bottom=0.26, top=0.79)
    fig.patch.set_facecolor("#fbfcfd")
    ax.set_facecolor("#fbfcfd")
    for point in (0, slot, 2 * slot, end):
        ax.axvline(point, color="#708395", lw=1.0, zorder=0)
    ax.axvspan(slot, 2 * slot, color="#eaf0f6", alpha=0.55, zorder=0)
    for point in (att, collect, aggregate, initial, slot + att):
        ax.axvline(point, color="#8f9dab", lw=0.75, ls=":", zorder=1)
    if cohort.scenario == "combined":
        ax.axvspan(slot + collect, slot + aggregate, color="#edbc65", alpha=0.28, zorder=1)

    labels = []
    for i, row in enumerate(rows):
        pos = len(rows) - i
        values = cohort.rows[row]
        clipped = sum(not (0 <= value <= end) for value in values)
        label = f"{row}\nn={len(values):,}"
        if row.startswith("Merge R"):
            ordinal = i - 2
            denominator = len(cohort.eligible)
            reached = len(cohort.rounds[ordinal])
            if denominator:
                label += f" · {reached}/{denominator} finished"
        if clipped:
            label += f" · {clipped} outside axis"
        labels.append(label)
        if values:
            ax.bxp(
                [box(values)], positions=[pos], widths=0.56, orientation="horizontal",
                patch_artist=True, showfliers=False, showmeans=show_mean,
                boxprops={"facecolor": "#82a8bf" if i < 3 else "#6d92bc", "edgecolor": "#34526e"},
                medianprops={"color": "#152a40", "linewidth": 1.7},
                capprops={"color": "#34526e"}, whiskerprops={"color": "#34526e"},
                meanprops={"marker": "D", "markerfacecolor": "white", "markeredgecolor": "#34526e", "markersize": 4},
                zorder=3,
            )
            for direction, predicate, at in (("<", lambda x: x < 0, 0), (">", lambda x: x > end, end)):
                if any(predicate(value) for value in values):
                    ax.plot(at, pos, direction, color="#a85426", clip_on=False, zorder=6)
        if cohort.ready[row]:
            ax.plot(
                statistics.median(cohort.ready[row]), pos - 0.31, marker="o", color="#26684b",
                ms=4, clip_on=True, zorder=4,
            )

    ax.set_yticks(range(len(rows), 0, -1), labels)
    ax.tick_params(axis="y", length=0, labelsize=9, pad=9)
    ax.set_xlim(0, end)
    ax.set_ylim(0.5, len(rows) + 0.65)
    ax.set_xlabel("Seconds from the reference vote slot", color="#26394c", labelpad=10)
    ax.spines[["left", "right", "top"]].set_visible(False)
    ax.spines["bottom"].set_color("#708395")
    for x, label in ((slot / 2, "Vote slot s"), (1.5 * slot, "Slot s+1"), (2.5 * slot, "Proposal slot s+2")):
        ax.text(x, len(rows) + 0.84, label, ha="center", color="#3d5368", size=10, clip_on=False)

    hardware = run["hardware"]
    cpu = hardware.get("cpu_model") or hardware.get("architecture") or "CPU unknown"
    profile = run.get("prover_cpu_profile") or "profile unknown"
    threads = run.get("prover_threads")
    worker_text = f"{threads} prover threads" if threads is not None else "prover threads unknown"
    fig.text(0.04, 0.95, "PQ attestation and proof timing", color="#152a40", size=19, weight="bold")
    fig.text(0.04, 0.904, f"{cohort.label}   |   {cpu}   |   {profile}, {worker_text}", color="#3d5368", size=10)
    reserve = f"  ·  +{slot + collect:g} to +{slot + aggregate:g} reserved" if cohort.scenario == "combined" else ""
    fig.text(
        0.04, 0.858,
        f"+{att:g} attest  ·  +{collect:g} collect  ·  +{aggregate:g} broadcast  ·  +{initial:g} initial trigger"
        f"  ·  +{slot + att:g} next attest  ·  +{2 * slot:g} nominal proposal{reserve}",
        color="#43586b", size=9,
    )
    marks = [Line2D([0], [0], color="#26684b", marker="o", lw=0, label="Median checked readiness")]
    if cohort.snapshots:
        snapshot = statistics.median(cohort.snapshots)
        ax.axvline(snapshot, color="#7e4d73", ls="--", lw=1.2, zorder=2)
        marks.append(Line2D([0], [0], color="#7e4d73", ls="--", label=f"Median actual snapshot {snapshot:.2f}s"))
    ax.legend(handles=marks, bbox_to_anchor=(1, -0.18), loc="upper right", frameon=False, fontsize=9)
    fig.text(0.04, 0.155, "Message-weighted first receipts. Boxes P25–P75, median line, P5/P95 whiskers.", color="#43586b", size=9)
    health = run.get("recorder_status", {})
    dropped = sum(health.get("dropped", {}).values())
    outcomes = "  ·  ".join(f"{label.replace('_', ' ')} {count:,}" for label, count in sorted(cohort.outcomes.items()))
    from textwrap import fill
    fig.text(
        0.04, 0.115,
        fill(outcomes or "No experiment outcomes recorded.", 150),
        color="#43586b", size=8, va="top",
    )
    fig.text(
        0.04, 0.03,
        f"Recorder dropped {dropped:,}; evicted chunks {health.get('evicted_chunks', 0):,}; "
        f"disk failure {'yes' if health.get('disk_failed') else 'no'}.",
        color="#43586b", size=8,
    )
    fig.savefig(output.with_suffix(".png"))
    fig.savefig(output.with_suffix(".svg"))
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path, help="Directory containing run.json and finalized events")
    parser.add_argument("--output", required=True, type=Path, help="Directory for the PNG and SVG charts")
    parser.add_argument("--scenario", help="Render only this scenario, e.g. combined or proposer_only")
    parser.add_argument("--mean", action="store_true", help="Show arithmetic means in addition to medians")
    args = parser.parse_args()
    try:
        run = json.loads((args.run / "run.json").read_text())
        if run["schema_version"] != 1:
            raise ValueError(f"Unsupported event schema {run['schema_version']}")
        cohorts = summarize(run, read_records(args.run, run))
        args.output.mkdir(parents=True, exist_ok=True)
        rendered = 0
        for (scenario, committees, active), cohort in cohorts.items():
            if args.scenario is not None and scenario != args.scenario:
                continue
            suffix = re.sub(r"[^a-zA-Z0-9_-]+", "-", scenario)
            if committees is not None:
                suffix += f"-c{committees}"
            if active is not None:
                suffix += f"-n{active}"
            if not re.fullmatch(r"[a-zA-Z0-9_-]+", run["run_id"]):
                raise ValueError("Invalid run identifier")
            name = f"{run['run_id']}-{suffix}"
            render(run, cohort, args.output / name, show_mean=args.mean)
            print(args.output / f"{name}.png")
            rendered += 1
        if not rendered:
            raise ValueError("No matching cohort found")
    except (OSError, ValueError, KeyError, ImportError) as error:
        parser.exit(1, f"PQ timing report failed: {error}\n")


if __name__ == "__main__":
    main()
