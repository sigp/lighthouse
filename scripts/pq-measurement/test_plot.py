"""Check normalization and cohort/round handling independently of Matplotlib."""

import unittest

from plot import COMMITTEE, ARRIVALS, box, offset_seconds, summarize


RUN = {"genesis_time": 1000, "genesis_slot": 0, "timing": {"slot_ns": 12_000_000_000}}


def event(kind, reference=100, offset=0, **fields):
    return {
        "kind": kind, "reference_slot": reference, "mono_ns": 1000 + offset,
        "wall_ns": (1000 + reference * 12 + offset) * 1_000_000_000, **fields,
    }


class TimingTest(unittest.TestCase):
    def test_offsets_retain_late_messages(self):
        self.assertEqual(offset_seconds(event("message_received", offset=13), RUN), 13)
        self.assertEqual(offset_seconds(event("message_received", offset=-1), RUN), -1)
        self.assertEqual(box([0, 10])["whishi"], 9.5)

    def test_reuse_and_failures_do_not_create_backend_samples(self):
        tags = dict(
            experiment_id=100, sequence_id="measurement:100",
            scenario="combined", committee_count=2, active_validators=512,
        )
        received = dict(source="network", message_kind="individual", message_id="single")
        records = [
            event("experiment_planned", target_slot=102, outcome="planned", **tags),
            event("message_received", offset=13, **received),
            event("message_received", offset=14, **received),
            event("message_received", source="measurement", message_kind="aggregate", message_id="private", offset=5),
            event("job_outcome", work="initial", round=1, outcome="reused", **tags),
            event("proof_finished", work="improvement", round=2, outcome="success", offset=16, **tags),
            event("candidate_ready", work="improvement", round=2, outcome="ready", offset=17, **tags),
            event("proof_finished", work="improvement", round=3, outcome="failed", offset=22, **tags),
            event("proof_finished", work="improvement", round=4, outcome="success", offset=38, late=True, **tags),
            event("proof_finished", reference=101, work="committee", round=0, outcome="success", offset=5, **tags),
            event("proposal_snapshot", offset=24, outcome="ready", **tags),
            event("experiment_planned", reference=109, scenario="combined", outcome="local_validators"),
        ]
        key = "combined", 2, 512
        cohort = summarize(RUN, records)[key]
        self.assertEqual(cohort.rows[ARRIVALS["individual"]], [13])
        self.assertEqual(cohort.rows[ARRIVALS["aggregate"]], [])
        self.assertEqual(cohort.rows["Merge R1 backend finished"], [])
        self.assertEqual(cohort.rows["Merge R2 backend finished"], [16])
        self.assertEqual(cohort.rows["Merge R4 backend finished"], [38])
        self.assertEqual(cohort.ready["Merge R2 backend finished"], [17])
        self.assertEqual(cohort.rows[COMMITTEE], [5])
        self.assertEqual(cohort.outcomes["backend failure"], 1)
        self.assertEqual(cohort.outcomes["skipped local_validators"], 1)
        self.assertEqual(cohort.outcomes["late backend finish"], 1)
        self.assertEqual(cohort.outcomes["receipts without terminal validation"], 1)


if __name__ == "__main__":
    unittest.main()
