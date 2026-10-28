import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from serial_deck import metrics, profiles
from serial_deck.metrics import MetricsError, clean_rule, clean_rules, merge_rules


def rule(**over):
    base = {"id": "heap_free", "label": "Free", "before": "free="}
    base.update(over)
    return base


class CleanRuleTest(unittest.TestCase):
    def test_valid_rule_defaults(self):
        got = clean_rule(rule())
        self.assertEqual(got, {"id": "heap_free", "label": "Free", "before": "free=", "unit": "", "tag": "",
                               "scale": 1.0, "warn_below": None, "warn_above": None, "pin": False})

    def test_valid_rule_keeps_every_field(self):
        got = clean_rule(rule(unit="KB", tag="sys", scale=0.5, warn_below=1, warn_above=9.5, pin=True))
        self.assertEqual((got["unit"], got["tag"], got["scale"], got["warn_below"], got["warn_above"], got["pin"]),
                         ("KB", "sys", 0.5, 1, 9.5, True))

    def test_unknown_key_regex_refused(self):
        with self.assertRaisesRegex(MetricsError, "regex"):
            clean_rule(rule(regex="(\\d+)"))

    def test_bad_id_long_label_long_before_control_chars(self):
        for bad in (rule(id="Bad"), rule(id="1x"), rule(id="a" * 33), rule(label="x" * 41), rule(label=""),
                    rule(before=""), rule(before="x" * 65), rule(before="a\nb"), rule(unit="123456789"),
                    rule(label="a\tb"), rule(tag="a\nb")):
            with self.assertRaises(MetricsError, msg=bad):
                clean_rule(bad)

    def test_missing_required_key_refused(self):
        for key in ("id", "label", "before"):
            raw = rule()
            del raw[key]
            with self.assertRaises(MetricsError, msg=key):
                clean_rule(raw)

    def test_bool_and_inf_scale_refused(self):
        for bad in (True, float("inf"), float("nan"), "2", 0):
            with self.assertRaises(MetricsError, msg=repr(bad)):
                clean_rule(rule(scale=bad))
        for bad in (True, float("inf"), "1"):
            with self.assertRaises(MetricsError, msg=repr(bad)):
                clean_rule(rule(warn_below=bad))

    def test_absent_or_null_scale_means_one(self):
        self.assertEqual(clean_rule(rule(scale=None))["scale"], 1.0)
        self.assertEqual(clean_rule(rule())["scale"], 1.0)

    def test_pin_must_be_bool(self):
        with self.assertRaises(MetricsError):
            clean_rule(rule(pin=1))

    def test_not_a_dict_refused(self):
        with self.assertRaises(MetricsError):
            clean_rule(["id"])


class CleanRulesTest(unittest.TestCase):
    def test_duplicate_ids_refused(self):
        with self.assertRaisesRegex(MetricsError, "duplicate"):
            clean_rules([rule(), rule(label="Other")])

    def test_more_than_32_refused(self):
        many = [rule(id=f"m{i}") for i in range(33)]
        with self.assertRaises(MetricsError):
            clean_rules(many)
        self.assertEqual(len(clean_rules(many[:32])), 32)

    def test_not_a_list_refused(self):
        with self.assertRaises(MetricsError):
            clean_rules({"rules": []})


class MergeTest(unittest.TestCase):
    def test_merge_user_overrides_profile_by_id(self):
        profile = clean_rules([rule(id="a", label="A"), rule(id="b", label="B")])
        user = clean_rules([rule(id="b", label="B2"), rule(id="c", label="C")])
        merged = merge_rules(profile, user)
        self.assertEqual([(r["id"], r["label"]) for r in merged], [("a", "A"), ("b", "B2"), ("c", "C")])

    def test_33_user_plus_profile_rules_refused_on_merge(self):
        profile = clean_rules([rule(id=f"p{i}") for i in range(20)])
        user = clean_rules([rule(id=f"u{i}") for i in range(13)])
        with self.assertRaisesRegex(MetricsError, "32"):
            merge_rules(profile, user)

    def test_override_does_not_count_twice(self):
        profile = clean_rules([rule(id=f"p{i}") for i in range(32)])
        user = clean_rules([rule(id="p0", label="mine")])
        self.assertEqual(len(merge_rules(profile, user)), 32)


class FileLayerTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = Path(self.dir.name) / "metrics.json"

    def test_metrics_path_env_override(self):
        old = os.environ.get("SERIAL_DECK_METRICS_FILE")
        os.environ["SERIAL_DECK_METRICS_FILE"] = str(self.path)
        try:
            self.assertEqual(metrics.metrics_path(), self.path)
        finally:
            if old is None:
                del os.environ["SERIAL_DECK_METRICS_FILE"]
            else:
                os.environ["SERIAL_DECK_METRICS_FILE"] = old

    def test_metrics_path_default_is_in_config_dir(self):
        old = os.environ.pop("SERIAL_DECK_METRICS_FILE", None)
        try:
            self.assertEqual(metrics.metrics_path().name, "metrics.json")
        finally:
            if old is not None:
                os.environ["SERIAL_DECK_METRICS_FILE"] = old

    def test_load_missing_is_empty_no_problem(self):
        self.assertEqual(metrics.load_user_rules(self.path), ([], "", ""))

    def test_load_invalid_json_returns_problem_and_rev_not_raise(self):
        self.path.write_text("{not json", encoding="utf-8")
        rules, problem, rev = metrics.load_user_rules(self.path)
        self.assertEqual(rules, [])
        self.assertIn("JSON", problem)
        self.assertEqual(len(rev), 40)

    def test_load_invalid_rule_returns_problem(self):
        self.path.write_text(json.dumps({"rules": [rule(regex="x")]}), encoding="utf-8")
        rules, problem, _ = metrics.load_user_rules(self.path)
        self.assertEqual(rules, [])
        self.assertIn("regex", problem)

    def test_load_wrong_shape_returns_problem(self):
        self.path.write_text(json.dumps([1, 2]), encoding="utf-8")
        self.assertIn("rules", metrics.load_user_rules(self.path)[1])

    def test_load_oversized_returns_problem(self):
        self.path.write_text(" " * (16 * 1024 + 1), encoding="utf-8")
        rules, problem, rev = metrics.load_user_rules(self.path)
        self.assertEqual(rules, [])
        self.assertIn("16", problem)
        self.assertEqual(len(rev), 40)

    def test_save_roundtrip_returns_rev_and_leaves_no_temp_files(self):
        saved = clean_rules([rule(unit="KB", scale=0.25)])
        rev = metrics.save_user_rules(saved, "", self.path)
        self.assertEqual(metrics.load_user_rules(self.path), (saved, "", rev))
        self.assertEqual([p.name for p in self.path.parent.iterdir()], ["metrics.json"])

    def test_save_stale_rev_refused_file_unchanged(self):
        rev = metrics.save_user_rules([rule()], "", self.path)
        before = self.path.read_bytes()
        with self.assertRaisesRegex(MetricsError, "stale"):
            metrics.save_user_rules([rule(id="other")], "not-the-rev", self.path)
        self.assertEqual(self.path.read_bytes(), before)
        metrics.save_user_rules([rule(id="other")], rev, self.path)  # the right rev works

    def test_save_with_empty_base_rev_over_existing_file_is_stale(self):
        metrics.save_user_rules([rule()], "", self.path)
        with self.assertRaisesRegex(MetricsError, "stale"):
            metrics.save_user_rules([rule(id="other")], "", self.path)

    def test_save_over_16kib_refused_file_unchanged(self):
        rev = metrics.save_user_rules([rule()], "", self.path)
        before = self.path.read_bytes()
        # 32 rules at every per-field character limit: only multi-byte text (e.g. Vietnamese labels) passes 16 KiB.
        big = [rule(id=f"m{i}", before="ế" * 64, label="ế" * 40, unit="ế" * 8, tag="ế" * 64) for i in range(32)]
        with self.assertRaisesRegex(MetricsError, "16"):
            metrics.save_user_rules(big, rev, self.path)
        self.assertEqual(self.path.read_bytes(), before)

    def test_save_invalid_rules_refused_file_unchanged(self):
        with self.assertRaises(MetricsError):
            metrics.save_user_rules([rule(regex="x")], "", self.path)
        self.assertFalse(self.path.exists())

    @unittest.skipUnless(os.name == "posix", "owner-only mode is a POSIX concept")
    def test_saved_file_is_owner_only(self):
        metrics.save_user_rules([rule()], "", self.path)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)


class ProfileMetricsTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        env = patch.dict(os.environ, {"SERIAL_DECK_PROFILE_DIR": self.dir.name})
        env.start()
        self.addCleanup(env.stop)

    def write(self, name, data):
        (Path(self.dir.name) / f"{name}.json").write_text(json.dumps(data), encoding="utf-8")

    def test_profile_accepts_metrics_list(self):
        self.write("board", {"label": "Board", "metrics": [rule(unit="KB", scale=0.5)]})
        found, problems = profiles.load_all()
        self.assertEqual(problems, {})
        self.assertEqual(found["board"]["metrics"], [clean_rule(rule(unit="KB", scale=0.5))])

    def test_bad_metric_is_a_profile_problem_other_profiles_still_load(self):
        self.write("bad", {"metrics": [rule(regex="(\\d+)")]})
        self.write("good", {"metrics": [rule()]})
        found, problems = profiles.load_all()
        self.assertIn("good", found)
        self.assertNotIn("bad", found)
        self.assertIn("regex", problems["bad.json"])

    def test_profile_without_metrics_unchanged(self):
        self.write("plain", {"label": "Plain", "default_baud": 115200})
        found, problems = profiles.load_all()
        self.assertEqual(problems, {})
        self.assertNotIn("metrics", found["plain"])

    def test_metrics_must_be_a_list_of_valid_rules(self):
        self.write("odd", {"metrics": {"id": "x"}})
        self.assertIn("rules must be a list", profiles.load_all()[1]["odd.json"])


if __name__ == "__main__":
    unittest.main()
