"""Offline tests: the LLM is replaced with prepared responses."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import findmythreats as tm

ARCHITECTURE = {
    "components": [
        {"id": "C1", "name": "User", "type": "external entity", "description": "Actor"},
        {"id": "C2", "name": "Frontend", "type": "process", "description": "Web | interface"},
        {"id": "C3", "name": "Backend", "type": "process", "description": "API"},
        {"id": "C4", "name": "DB", "type": "data store", "description": "Data"},
    ],
    "data_flows": [
        {"id": "F1", "source": "C1", "target": "C2", "protocol": "HTTPS", "description": "Requests"},
        {"id": "F2", "source": "C2", "target": "C3", "protocol": "HTTP", "description": "API"},
        {"id": "F3", "source": "C3", "target": "C4", "protocol": "", "description": "Queries"},
    ],
}
THREATS = {
    "threats": [
        {"id": "T1", "element_id": "F2", "stride": "Information Disclosure", "title": "Cleartext traffic", "description": "HTTP could expose data."},
        {"id": "T2", "element_id": "C2", "stride": "Spoofing", "title": "Spoofing", "description": "If authentication is insufficient."},
    ]
}
MAPPINGS = {
    "mappings": [
        {"threat_id": "T1", "control_ids": ["TRANS-001"], "recommendation": "Use TLS."},
        {"threat_id": "T2", "control_ids": ["AUTH-001"], "recommendation": "Apply MFA where appropriate."},
    ]
}


def fake_chat(answers):
    def chat(self, prompt, image=None):
        step = "architecture" if image else "threats" if "Identify security threats" in prompt else "mappings"
        answer = answers[step]
        return answer.pop(0) if isinstance(answer, list) else answer

    return chat


class FindMyThreatsTests(unittest.TestCase):
    def test_control_catalog(self):
        controls = tm.load_controls()
        self.assertEqual(15, len(controls))
        counts = {}
        for control in controls:
            counts[control["category"]] = counts.get(control["category"], 0) + 1
        self.assertEqual(5, len(counts))
        self.assertEqual({3}, set(counts.values()))

    def test_validation_rejects_unknown_references(self):
        bad_arch = {**ARCHITECTURE, "data_flows": [{**ARCHITECTURE["data_flows"][0], "target": "C99"}]}
        with self.assertRaises(ValueError):
            tm.validate_architecture(bad_arch)

        bad_threats = {"threats": [{**THREATS["threats"][0], "element_id": "C99"}]}
        with self.assertRaises(ValueError):
            tm.validate_threats(bad_threats, ARCHITECTURE)

        bad_mappings = {"mappings": [{**MAPPINGS["mappings"][0], "control_ids": ["UNKNOWN"]}, MAPPINGS["mappings"][1]]}
        with self.assertRaisesRegex(ValueError, "UNKNOWN"):
            tm.validate_mappings(bad_mappings, THREATS["threats"], tm.load_controls())

    def test_pipeline_and_retry(self):
        answers = {
            "architecture": ["no es JSON", json.dumps(ARCHITECTURE)],
            "threats": json.dumps(THREATS),
            "mappings": json.dumps(MAPPINGS),
        }
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(tm.LLM, "chat", fake_chat(answers)):
            root = Path(folder)
            image = root / "diagram.png"
            image.write_bytes(b"\x89PNG")
            output_root = root / "out"

            code = tm.main([str(image), "--model", "test", "--out-dir", str(output_root)])
            self.assertEqual(0, code)
            runs = list(output_root.iterdir())
            self.assertEqual(1, len(runs))
            out = runs[0]
            self.assertRegex(out.name, r"^diagram-\d{8}-\d{6}-[a-z0-9]{4}$")
            self.assertEqual(b"\x89PNG", (out / "diagram.png").read_bytes())
            self.assertEqual(ARCHITECTURE, json.loads((out / "1_components.json").read_text("utf-8")))
            self.assertEqual(THREATS["threats"], json.loads((out / "2_threats.json").read_text("utf-8")))
            self.assertEqual(MAPPINGS["mappings"], json.loads((out / "3_mappings.json").read_text("utf-8")))

            report = (out / "4_threat_model.md").read_text("utf-8")
            self.assertIn("Web \\| interface", report)
            self.assertIn("| T1 | Frontend → Backend | Information Disclosure |", report)
            self.assertIn("| T1 | TRANS-001 | Use TLS. |", report)
            self.assertIn("## 4. Selected Security Controls", report)
            self.assertIn(
                "Controls referenced in this threat model: 2 of 15 from `m6t1_en.json`.",
                report,
            )
            self.assertIn("| TRANS-001 | Data in transit |", report)
            self.assertNotIn("| SEC-003 |", report)

    def test_pipeline_reports_progress(self):
        answers = {
            "architecture": json.dumps(ARCHITECTURE),
            "threats": json.dumps(THREATS),
            "mappings": json.dumps(MAPPINGS),
        }
        events = []
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(tm.LLM, "chat", fake_chat(answers)):
            root = Path(folder)
            image = root / "diagram.png"
            image.write_bytes(b"\x89PNG")
            tm.run_pipeline(
                tm.LLM("http://example.test/v1", "test", "test"),
                image,
                root / "out",
                progress=lambda step, message: events.append((step, message)),
            )

        self.assertEqual([1, 2, 3, 4], [step for step, _ in events])
        self.assertEqual("Extracting components", events[0][1])
        self.assertEqual("Generating report", events[-1][1])

    def test_custom_control_catalog_with_required_fields_only(self):
        custom_controls = [
            {
                "id": "CUSTOM-001",
                "category": "Custom",
                "name": "Example control",
                "description": "A minimal custom control.",
            }
        ]
        custom_mappings = {
            "mappings": [
                {"threat_id": "T1", "control_ids": ["CUSTOM-001"], "recommendation": "Apply the control."},
                {"threat_id": "T2", "control_ids": ["CUSTOM-001"], "recommendation": "Apply the control."},
            ]
        }
        answers = {
            "architecture": json.dumps(ARCHITECTURE),
            "threats": json.dumps(THREATS),
            "mappings": json.dumps(custom_mappings),
        }

        with tempfile.TemporaryDirectory() as folder, mock.patch.object(tm.LLM, "chat", fake_chat(answers)):
            root = Path(folder)
            controls_file = root / "custom.json"
            controls_file.write_text(json.dumps(custom_controls), encoding="utf-8")
            image = root / "diagram.png"
            image.write_bytes(b"\x89PNG")
            output_root = root / "out"

            code = tm.main([
                str(image), "--model", "test", "--controls", str(controls_file), "--out-dir", str(output_root)
            ])
            self.assertEqual(0, code)
            runs = list(output_root.iterdir())
            self.assertEqual(1, len(runs))
            out = runs[0]

            loaded = tm.load_controls(controls_file)
            self.assertEqual("", loaded[0]["implementation"])
            self.assertEqual([], loaded[0]["references"])
            self.assertEqual([], loaded[0]["stride"])

            report = (out / "4_threat_model.md").read_text("utf-8")
            self.assertIn("`custom.json`", report)
            self.assertIn("CUSTOM-001", report)

    def test_run_directory_sanitizes_filename(self):
        with tempfile.TemporaryDirectory() as folder:
            run_dir = tm.create_run_directory("$(touch pwned).png", Path(folder))
            self.assertRegex(run_dir.name, r"^touch-pwned-\d{8}-\d{6}-[a-z0-9]{4}$")

    def test_web_control_catalogs_lists_json_files_only(self):
        import web

        with tempfile.TemporaryDirectory() as folder, mock.patch.object(web, "CONTROLS", Path(folder)):
            controls_dir = Path(folder)
            (controls_dir / "m6t1_en.json").write_text("[]", encoding="utf-8")
            (controls_dir / "m6t1_es.json").write_text("[]", encoding="utf-8")
            (controls_dir / "notes.txt").write_text("ignore", encoding="utf-8")
            (controls_dir / "nested.json").mkdir()

            catalogs = web.control_catalogs()
            self.assertEqual(["m6t1_en.json", "m6t1_es.json"], list(catalogs))
            self.assertEqual(controls_dir / "m6t1_en.json", catalogs["m6t1_en.json"])
            self.assertEqual("m6t1_en.json", web.DEFAULT_CONTROLS)
            self.assertIsNone(catalogs.get("../m6t1_en.json"))

    def test_web_markdown_renderer_escapes_html(self):
        import web

        rendered = web.markdown_to_html(
            "# Report\n\n| A | B |\n| --- | --- |\n| x | <script>alert(1)</script> |"
        )
        self.assertIn("<h1>Report</h1>", rendered)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", rendered)

    def test_web_markdown_renderer_supports_fenced_code(self):
        import web

        rendered = web.markdown_to_html("```bash\npython web.py\n```")
        self.assertIn("<pre><code>python web.py</code></pre>", rendered)

    def test_web_report_page_sets_base_for_run_assets(self):
        import web

        rendered = web.render_page(
            "![Architecture diagram](diagram.png)",
            "Threat Model",
            "/diagram-20261004-120000-ab12/",
        )
        self.assertIn('<base href="/diagram-20261004-120000-ab12/">', rendered)
        self.assertIn('src="diagram.png"', rendered)

    def test_web_available_reports_only_lists_runs_with_reports(self):
        import web

        with tempfile.TemporaryDirectory() as folder, mock.patch.object(web, "OUTPUT", Path(folder)):
            output = Path(folder)
            valid = output / "diagram-20261004-120000-ab12"
            valid.mkdir()
            (valid / "4_threat_model.md").write_text("# Report", encoding="utf-8")
            (output / "incomplete-run").mkdir()
            (output / "not-a-run.txt").write_text("ignore", encoding="utf-8")

            reports = web.available_reports()
            self.assertEqual([valid.name], list(reports))
            self.assertIsNone(reports.get("../README.md"))


if __name__ == "__main__":
    unittest.main()
