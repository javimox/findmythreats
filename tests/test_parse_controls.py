"""Tests for the small NIST OSCAL control converter."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import findmythreats
import parse_controls


SAMPLE_OSCAL = {
    "catalog": {
        "params": [{"id": "global_prm", "label": "organization-defined value"}],
        "groups": [
            {
                "id": "ac",
                "title": "Access Control",
                "controls": [
                    {
                        "id": "ac-1",
                        "title": "Policy and Procedures",
                        "params": [
                            {"id": "ac-1_prm_1", "label": "organization-defined personnel"},
                            {
                                "id": "ac-01_odp.03",
                                "select": {
                                    "how-many": "one-or-more",
                                    "choice": [
                                        "organization-level",
                                        "mission/business process-level",
                                        "system-level",
                                    ],
                                },
                            },
                        ],
                        "props": [
                            {"name": "label", "value": "AC-01"},
                            {"name": "label", "value": "AC-1"},
                        ],
                        "parts": [
                            {
                                "name": "statement",
                                "prose": (
                                    "Provide access control policy to {{ insert: param, ac-1_prm_1 }} at "
                                    "{{ insert: param, ac-01_odp.03 }} scope."
                                ),
                            },
                            {"name": "guidance", "prose": "Coordinate the policy with {{ insert: param, global_prm }}."},
                        ],
                        "controls": [
                            {
                                "id": "ac-1.1",
                                "title": "Enhancement",
                                "props": [{"name": "label", "value": "AC-1(1)"}],
                                "parts": [{"name": "statement", "prose": "Nested enhancement."}],
                            }
                        ],
                    },
                    {
                        "id": "ac-13",
                        "title": "Supervision and Review — Access Control",
                        "props": [{"name": "status", "value": "Withdrawn"}],
                        "parts": [],
                    },
                ],
            },
            {
                "id": "ia",
                "title": "Identification and Authentication",
                "controls": [
                    {
                        "id": "ia-1",
                        "title": "IA Policy",
                        "props": [{"name": "label", "value": "IA-1"}],
                        "parts": [{"name": "statement", "prose": "Define an authentication policy."}],
                    }
                ],
            },
        ],
    }
}


class ParseControlsTests(unittest.TestCase):
    def test_nist_family_conversion(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "nist.json"
            source.write_text(json.dumps(SAMPLE_OSCAL), encoding="utf-8")

            controls = parse_controls.parse_nist(source, {"AC"})

            self.assertEqual(1, len(controls))
            self.assertEqual("AC-1", controls[0]["id"])
            self.assertEqual("Access Control", controls[0]["category"])
            self.assertIn("[organization-defined personnel]", controls[0]["description"])
            self.assertIn("one or more of", controls[0]["description"])
            self.assertIn("organization-level", controls[0]["description"])
            self.assertIn("[organization-defined value]", controls[0]["implementation"])
            self.assertEqual([], controls[0]["stride"])
            self.assertNotIn("{{ insert:", json.dumps(controls))

    def test_generated_catalog_is_accepted_by_findmythreats(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "nist.json"
            output = root / "controls.json"
            source.write_text(json.dumps(SAMPLE_OSCAL), encoding="utf-8")

            code = parse_controls.main([
                "nist", str(source), "--families", "AC,IA", "--output", str(output)
            ])

            self.assertEqual(0, code)
            self.assertEqual(2, len(findmythreats.load_controls(output)))

    def test_render_accepts_spacing_and_nested_parameter_inserts(self):
        params = {
            "outer": "{{ insert: param , inner }}",
            "inner": "resolved value",
        }
        rendered = parse_controls._render("Use {{ insert : param , outer }}.", params)
        self.assertEqual("Use resolved value.", rendered)

    def test_unsupported_insert_reports_expression(self):
        with self.assertRaisesRegex(ValueError, r"insert: prop, example"):
            parse_controls._render("Use {{ insert: prop, example }}.", {})

    def test_unknown_family_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "nist.json"
            source.write_text(json.dumps(SAMPLE_OSCAL), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "ZZ"):
                parse_controls.parse_nist(source, {"ZZ"})


if __name__ == "__main__":
    unittest.main()
