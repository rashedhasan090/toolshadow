import json
import os
import tempfile
import unittest

from toolshadow.core import (Tool, check_catalog, check_lock, edit_distance, load_catalog,
                             make_lock, skeleton)
from toolshadow.cli import main

EX = os.path.join(os.path.dirname(__file__), "..", "examples")
DUMPS = [os.path.join(EX, f) for f in ("filesystem.json", "mail.json", "weather-plus.json")]


def rules(findings):
    return sorted({f.rule for f in findings})


class SkeletonTests(unittest.TestCase):
    def test_homoglyph_and_case(self):
        self.assertEqual(skeleton("read_file"), skeleton("Read-Fіle"))  # Cyrillic i
        self.assertEqual(skeleton("read_fiIe".replace("I", "l")), "readfile")

    def test_edit_distance(self):
        self.assertEqual(edit_distance("readfile", "readfiie"), 1)
        self.assertGreater(edit_distance("abc", "xyzxyz", 1), 1)


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.tools = load_catalog(DUMPS)

    def test_loads_all(self):
        self.assertEqual(len(self.tools), 6)
        self.assertEqual({t.server for t in self.tools}, {"filesystem", "mail", "weather-plus"})

    def test_collision(self):
        f = [x for x in check_catalog(self.tools) if x.rule == "TS001"]
        self.assertEqual(len(f), 1)
        self.assertIn("send_email", f[0].message)

    def test_confusable(self):
        f = [x for x in check_catalog(self.tools) if x.rule == "TS002"]
        self.assertTrue(any("read_fiIe" in x.message for x in f))

    def test_cross_reference_imperative(self):
        f = [x for x in check_catalog(self.tools) if x.rule == "TS003"]
        hit = [x for x in f if "weather-plus/get_forecast" in x.tools]
        self.assertTrue(hit)
        self.assertEqual(hit[0].severity, "high")
        self.assertIn("bcc", hit[0].evidence)

    def test_no_self_server_reference(self):
        tools = [Tool("a", "list_items", "List items."), Tool("a", "get_item", "Use list_items first."),
                 Tool("b", "list_items", "Other list.")]
        f = [x for x in check_catalog(tools) if x.rule == "TS003"]
        self.assertEqual(f, [])

    def test_lookalike(self):
        f = [x for x in check_catalog(self.tools) if x.rule == "TS004"]
        self.assertTrue(any("read_fiIe" in " ".join(x.tools) for x in f))

    def test_hidden(self):
        f = [x for x in check_catalog(self.tools) if x.rule == "TS005"]
        self.assertEqual(len(f), 1)
        self.assertIn("U+200B", f[0].evidence)

    def test_tag_text_decoded(self):
        hidden = "".join(chr(0xE0000 + ord(c)) for c in "hi")
        f = check_catalog([Tool("s", "t", "ok" + hidden)])
        self.assertIn("'hi'", f[0].evidence)

    def test_clean_catalog(self):
        tools = [Tool("a", "list_repos", "List GitHub repositories."),
                 Tool("b", "get_weather", "Weather for a city.")]
        self.assertEqual(check_catalog(tools), [])


class LockTests(unittest.TestCase):
    def test_rug_pull_new_removed(self):
        before = [Tool("s", "a", "x"), Tool("s", "b", "y")]
        lock = make_lock(before)
        after = [Tool("s", "a", "x CHANGED"), Tool("s", "c", "z"), Tool("n", "d", "w")]
        self.assertEqual(rules(check_lock(after, lock)), ["TS101", "TS102", "TS103"])

    def test_unchanged_is_clean(self):
        t = [Tool("s", "a", "x", {"type": "object"})]
        self.assertEqual(check_lock(t, make_lock(t)), [])


class CliTests(unittest.TestCase):
    def test_fail_on_and_json(self):
        self.assertEqual(main(["scan", *DUMPS, "--fail-on", "high", "--format", "json"]), 1)

    def test_lock_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            lp = os.path.join(d, "lock.json")
            self.assertEqual(main(["lock", *DUMPS, "-o", lp]), 0)
            self.assertEqual(json.load(open(lp))["version"], 1)
            self.assertEqual(main(["scan", DUMPS[0], "--lock", lp, "--fail-on", "low"]), 0)

    def test_jsonrpc_shape(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "srv.json")
            json.dump({"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "x1"}]}}, open(p, "w"))
            self.assertEqual(load_catalog([p])[0].server, "srv")

    def test_bad_file(self):
        self.assertEqual(main(["scan", "/nonexistent.json"]), 2)


if __name__ == "__main__":
    unittest.main()
