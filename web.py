#!/usr/bin/env python3
"""Interfaz web ligera para findmythreats.py. Solo biblioteca estándar.

    python web.py [puerto]        # http://127.0.0.1:8000

La web es solo una capa de presentación: reutiliza run_pipeline() sin duplicar lógica.
"""

import html
import json
import re
import sys
import time
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

from findmythreats import LLM, LLMError, create_run_directory, run_pipeline

ROOT = Path(__file__).resolve().parent
PAGE = ROOT / "web.html"
OUTPUT = ROOT / "output"
CONTROLS = ROOT / "controls"
DEFAULT_CONTROLS = "m6t1.json"
IMAGE_TYPES = {"image/png": ".png", "image/jpeg": ".jpg", "image/webp": ".webp"}
MAX_UPLOAD = 20 * 1024 * 1024
ARTIFACTS = ("1_components.json", "2_threats.json", "3_mappings.json", "4_threat_model.md")
LIST_ITEM = re.compile(r"\s*([-*]|\d+\.) ")


def control_catalogs() -> dict[str, Path]:
    """Return selectable control catalogs from controls/."""
    return {path.name: path for path in sorted(CONTROLS.glob("*.json")) if path.is_file()}


REPORT_HEAD = """<!doctype html>
<html lang="es"><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src 'self'; style-src 'unsafe-inline'">
<title>Modelo de amenazas</title>
<style>
body{max-width:72rem;margin:0 auto;padding:2rem 1.5rem 3rem;color:#17212f;background:#fff;
font:1rem/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}h1{font-size:2rem}h2{margin:2.3rem 0 .7rem;
border-bottom:2px solid #17212f;padding-bottom:.35rem;font-size:1.25rem}table{width:100%;border-collapse:collapse;
margin:1rem 0;font-size:.9rem}th,td{padding:.5rem .65rem;border-bottom:1px solid #d5dbe3;text-align:left;
vertical-align:top}th{border-bottom:1.5px solid #17212f}td:first-child{font-weight:600}img{max-width:100%;
border:1px solid #d5dbe3;border-radius:.35rem}code{padding:.1rem .3rem;background:#f1f4f7;border-radius:.2rem}
</style>
"""


def markdown_to_html(markdown: str) -> str:
    """Renderiza el subconjunto de Markdown que genera findmythreats.py."""

    def inline(text: str) -> str:
        text = html.escape(text.replace("\\|", "|"))
        text = re.sub(r"!\[(.*?)\]\((.*?)\)", r'<img alt="\1" src="\2">', text)
        text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
        return re.sub(r"`(.+?)`", r"<code>\1</code>", text)

    def row(line: str, tag: str) -> str:
        cells = re.split(r"(?<!\\)\|", line.strip()[1:-1])
        return "<tr>" + "".join(f"<{tag}>{inline(cell.strip())}</{tag}>" for cell in cells) + "</tr>"

    blocks = []
    for block in re.split(r"\n\s*\n", markdown.strip()):
        lines = block.splitlines()
        if block.startswith("#"):
            level = len(block) - len(block.lstrip("#"))
            blocks.append(f"<h{level}>{inline(block.lstrip('# '))}</h{level}>")
        elif block.startswith("|") and len(lines) > 1:
            body = "".join(row(line, "td") for line in lines[2:])
            blocks.append(f"<table>{row(lines[0], 'th')}{body}</table>")
        elif all(LIST_ITEM.match(line) for line in lines):
            items = "".join(f"<li>{inline(LIST_ITEM.sub('', line, count=1))}</li>" for line in lines)
            blocks.append(f"<ul>{items}</ul>")
        else:
            blocks.append(f"<p>{'<br>'.join(map(inline, lines))}</p>")
    return "\n".join(blocks)


class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.reply(200, "text/html; charset=utf-8", PAGE.read_bytes())
        elif self.path == "/controls":
            catalogs = control_catalogs()
            names = list(catalogs)
            default = DEFAULT_CONTROLS if DEFAULT_CONTROLS in catalogs else (names[0] if names else None)
            self.reply_json(200, {"controls": names, "default": default})
        else:
            super().do_GET()

    def do_POST(self):
        if self.path != "/analyze":
            return self.reply_json(404, {"error": "Ruta no encontrada."})

        base_url = self.headers.get("X-LLM-URL", "")
        model = self.headers.get("X-LLM-Model", "")
        catalog_name = self.headers.get("X-Controls") or DEFAULT_CONTROLS
        controls_file = control_catalogs().get(catalog_name)
        suffix = IMAGE_TYPES.get(self.headers.get("Content-Type"))
        length = self.headers.get("Content-Length", "")
        size = int(length) if length.isdigit() else 0
        image_bytes = self.rfile.read(size) if 0 < size <= MAX_UPLOAD else b""

        if controls_file is None:
            return self.reply_json(400, {"error": "El catálogo de controles seleccionado no existe."})
        if not (base_url.startswith(("http://", "https://")) and model and suffix and image_bytes):
            return self.reply_json(400, {"error": "Indica URL, modelo y una imagen PNG, JPG o WebP de hasta 20 MB."})

        filename = Path(unquote(self.headers.get("X-File-Name") or f"diagram{suffix}")).name
        out_dir = create_run_directory(filename, OUTPUT)
        image = out_dir / f"diagram{suffix}"
        image.write_bytes(image_bytes)

        started = time.perf_counter()
        try:
            llm = LLM(base_url, self.headers.get("X-LLM-Key") or "ollama", model)
            report = run_pipeline(llm, image, out_dir, controls_file)
        except (LLMError, ValueError, OSError) as exc:
            return self.reply_json(502, {"error": str(exc)})

        report.with_suffix(".html").write_text(
            REPORT_HEAD + markdown_to_html(report.read_text(encoding="utf-8")), encoding="utf-8"
        )
        files = [
            {"name": name, "size": (out_dir / name).stat().st_size}
            for name in ARTIFACTS
            if (out_dir / name).is_file()
        ]
        self.reply_json(200, {
            "run": out_dir.name,
            "files": files,
            "elapsed": round(time.perf_counter() - started, 1),
        })

    def reply_json(self, status: int, data: dict) -> None:
        self.reply(status, "application/json", json.dumps(data).encode())

    def reply(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    OUTPUT.mkdir(exist_ok=True)
    server = ThreadingHTTPServer(("127.0.0.1", port), partial(Handler, directory=str(OUTPUT)))
    print(f"Abre http://127.0.0.1:{port} en el navegador (Ctrl+C para salir)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
