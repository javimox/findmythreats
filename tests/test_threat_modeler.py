"""Pruebas sin red: el LLM se sustituye por respuestas preparadas."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import threat_modeler as tm

ARCHITECTURE = {
    "components": [
        {"id": "C1", "name": "Usuario", "type": "entidad externa", "description": "Actor"},
        {"id": "C2", "name": "Frontend", "type": "proceso", "description": "Interfaz | web"},
        {"id": "C3", "name": "Backend", "type": "proceso", "description": "API"},
        {"id": "C4", "name": "DB", "type": "almacén de datos", "description": "Datos"},
    ],
    "data_flows": [
        {"id": "F1", "source": "C1", "target": "C2", "protocol": "HTTPS", "description": "Peticiones"},
        {"id": "F2", "source": "C2", "target": "C3", "protocol": "HTTP", "description": "API"},
        {"id": "F3", "source": "C3", "target": "C4", "protocol": "", "description": "Consultas"},
    ],
}
THREATS = {
    "threats": [
        {"id": "T1", "element_id": "F2", "stride": "Information Disclosure", "title": "Tráfico en claro", "description": "HTTP podría exponer datos."},
        {"id": "T2", "element_id": "C2", "stride": "Spoofing", "title": "Suplantación", "description": "Si la autenticación es insuficiente."},
    ]
}
MAPPINGS = {
    "mappings": [
        {"threat_id": "T1", "control_ids": ["TRANS-001"], "recommendation": "Usar TLS."},
        {"threat_id": "T2", "control_ids": ["AUTH-001"], "recommendation": "Aplicar MFA cuando corresponda."},
    ]
}


def fake_chat(answers):
    def chat(self, prompt, image=None):
        step = "architecture" if image else "threats" if "Identifica amenazas" in prompt else "mappings"
        answer = answers[step]
        return answer.pop(0) if isinstance(answer, list) else answer

    return chat


class ThreatModelerTests(unittest.TestCase):
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

        bad_mappings = {"mappings": [{**MAPPINGS["mappings"][0], "control_ids": ["INVENTADO"]}, MAPPINGS["mappings"][1]]}
        with self.assertRaises(ValueError):
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
            out = root / "out"

            code = tm.main([str(image), "--model", "test", "--out-dir", str(out)])
            self.assertEqual(0, code)
            self.assertEqual(ARCHITECTURE, json.loads((out / "1_components.json").read_text("utf-8")))
            self.assertEqual(THREATS["threats"], json.loads((out / "2_threats.json").read_text("utf-8")))
            self.assertEqual(MAPPINGS["mappings"], json.loads((out / "3_mappings.json").read_text("utf-8")))

            report = (out / "4_threat_model.md").read_text("utf-8")
            self.assertIn("Interfaz \\| web", report)
            self.assertIn("| T1 | Frontend → Backend | Information Disclosure |", report)
            self.assertIn("| T1 | TRANS-001 | Usar TLS. |", report)
            self.assertIn("| SEC-003 | Manejo de secretos |", report)

    def test_web_markdown_renderer_escapes_html(self):
        import web

        rendered = web.markdown_to_html(
            "# Informe\n\n| A | B |\n| --- | --- |\n| x | <script>alert(1)</script> |"
        )
        self.assertIn("<h1>Informe</h1>", rendered)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", rendered)


if __name__ == "__main__":
    unittest.main()
