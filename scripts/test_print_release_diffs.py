import os
from pathlib import Path
import runpy
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


class ReleaseDiffTests(unittest.TestCase):
    def test_get_commits_between_follows_next_page(self):
        requests = SimpleNamespace(get=Mock())
        script = Path(__file__).with_name("print_release_diffs.py")
        with patch.dict(sys.modules, {"requests": requests}), \
             patch.dict(os.environ, {"GITHUB_TOKEN": "test-token"}), \
             patch.object(sys, "argv", [str(script), "--base", "old", "--head", "new"]):
            namespace = runpy.run_path(str(script))
        next_url = "https://api.github.com/repos/sigp/lighthouse/compare/old...new?per_page=100&page=2"
        first_page = [{"sha": str(i)} for i in range(100)]
        last_page = [{"sha": "last"}]
        requests.get.side_effect = [
            SimpleNamespace(raise_for_status=Mock(), json=lambda: {"commits": first_page},
                            links={"next": {"url": next_url}}),
            SimpleNamespace(raise_for_status=Mock(), json=lambda: {"commits": last_page}, links={}),
        ]
        self.assertEqual(namespace["get_commits_between"]("old", "new"), first_page + last_page)
        self.assertEqual(requests.get.call_count, 2)
        self.assertEqual(requests.get.call_args.args[0], next_url)

    def test_failed_comparison_is_not_reported_as_complete(self):
        requests = SimpleNamespace(get=Mock())
        script = Path(__file__).with_name("print_release_diffs.py")
        with patch.dict(sys.modules, {"requests": requests}), \
             patch.dict(os.environ, {"GITHUB_TOKEN": "test-token"}), \
             patch.object(sys, "argv", [str(script), "--base", "old", "--head", "new"]):
            namespace = runpy.run_path(str(script))
        requests.get.return_value.raise_for_status.side_effect = RuntimeError("comparison failed")
        with self.assertRaisesRegex(RuntimeError, "comparison failed"):
            namespace["get_commits_between"]("old", "new")


if __name__ == "__main__":
    unittest.main()
