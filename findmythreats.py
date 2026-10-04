#!/usr/bin/env python3
"""FindMyThreats - Automatización del modelado de amenazas desde un diagrama.

Cuatro procesos: extracción, amenazas STRIDE, mapeo de controles e informe.
Solo usa la biblioteca estándar de Python.
"""

import argparse
import base64
import json
import mimetypes
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

BASE_URL = "http://localhost:11434/v1"
ROOT = Path(__file__).resolve().parent
DEFAULT_CONTROLS_FILE = ROOT / "controls" / "m6t1.json"
TYPES = ("entidad externa", "proceso", "almacén de datos")
STRIDE = (
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
)
SYSTEM_PROMPT = (
    "Eres un analista de ciberseguridad especializado en modelado de amenazas. "
    "Responde en español y respeta exactamente el formato solicitado."
)

PROMPT_ARCHITECTURE = """\
Analiza el diagrama de arquitectura adjunto y extrae sus componentes y flujos de datos.
No inventes elementos ni protocolos que no estén representados.

Usa únicamente estos tipos de componente: entidad externa, proceso, almacén de datos.
Devuelve exclusivamente JSON:
{
  "components": [{"id": "C1", "name": "...", "type": "proceso", "description": "..."}],
  "data_flows": [{"id": "F1", "source": "C1", "target": "C2", "protocol": "HTTPS", "description": "..."}]
}
Los IDs deben ser únicos. source y target deben referirse a componentes existentes.
Si un dato no aparece en el diagrama, usa una cadena vacía.
"""

PROMPT_THREATS = """\
Identifica amenazas de seguridad en la arquitectura aplicando STRIDE por elemento.

Guía:
- entidad externa: Spoofing, Repudiation
- proceso: las seis categorías STRIDE
- almacén de datos: Tampering, Information Disclosure, Denial of Service
- flujo de datos: Tampering, Information Disclosure, Denial of Service

No inventes elementos nuevos. Si una protección no aparece en el diagrama, no afirmes que
no existe: formula la amenaza de forma condicional.

Devuelve exclusivamente JSON:
{
  "threats": [{"id": "T1", "element_id": "C1 o F1", "stride": "Spoofing",
               "title": "título breve", "description": "cómo podría materializarse la amenaza"}]
}
"""

PROMPT_MAPPINGS = """\
Mapea cada amenaza con entre uno y tres controles del catálogo suministrado.
Usa únicamente IDs del catálogo y genera exactamente una entrada por amenaza.

Devuelve exclusivamente JSON:
{
  "mappings": [{"threat_id": "T1", "control_ids": ["AUTH-001"],
                "recommendation": "acción concreta para reducir la amenaza"}]
}
"""


class LLMError(RuntimeError):
    pass


def dump(value) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2)


def extract_json(text: str) -> dict:
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end < start:
        raise ValueError("la respuesta no contiene un objeto JSON")
    data = json.loads(text[start : end + 1])
    check(isinstance(data, dict), "la respuesta JSON no es un objeto")
    return data


class LLM:
    """Cliente mínimo para /chat/completions compatible con OpenAI."""

    def __init__(self, base_url: str, api_key: str, model: str) -> None:
        self.url = base_url.rstrip("/") + "/chat/completions"
        self.api_key = api_key
        self.model = model

    def chat(self, prompt: str, image: Path | None = None) -> str:
        content: str | list[dict] = prompt
        if image:
            mime = mimetypes.guess_type(image.name)[0] or "image/png"
            encoded = base64.b64encode(image.read_bytes()).decode("ascii")
            content = [
                {"type": "text", "text": prompt},
                {"type": "image_url", "image_url": {"url": f"data:{mime};base64,{encoded}"}},
            ]

        request = urllib.request.Request(
            self.url,
            data=json.dumps(
                {
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": content},
                    ],
                    "stream": False,
                }
            ).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=300) as response:
                data = json.load(response)
            result = data["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise LLMError(f"HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"Error consultando el LLM: {exc}") from exc

        if not isinstance(result, str) or not result.strip():
            raise LLMError("El LLM devolvió una respuesta vacía")
        return result.strip()

    def chat_json(self, prompt: str, validate, image: Path | None = None) -> dict:
        """Pide JSON y hace un único reintento si la respuesta no es válida."""
        last_error: Exception | None = None
        for attempt in range(2):
            raw = self.chat(prompt, image)
            try:
                data = extract_json(raw)
                validate(data)
                return data
            except (ValueError, KeyError, TypeError) as exc:
                last_error = exc
                if attempt == 0:
                    prompt += (
                        f"\n\nLa respuesta anterior no era válida: {exc}. "
                        "Corrígela y devuelve exclusivamente el JSON solicitado."
                    )
        raise LLMError(f"El modelo no devolvió una respuesta válida: {last_error}")


def check(condition, message: str) -> None:
    if not condition:
        raise ValueError(message)


def unique_ids(items: list[dict], what: str) -> set[str]:
    ids = [item["id"] for item in items]
    check(len(ids) == len(set(ids)), f"hay IDs de {what} duplicados")
    return set(ids)


def load_controls(path: Path = DEFAULT_CONTROLS_FILE) -> list[dict]:
    controls = json.loads(path.read_text(encoding="utf-8"))
    check(isinstance(controls, list) and controls, f"{path.name} debe contener una lista de controles")

    required = {"id", "category", "name", "description"}
    for index, control in enumerate(controls, start=1):
        check(isinstance(control, dict), f"control {index}: debe ser un objeto JSON")
        missing = required - control.keys()
        check(not missing, f"control {index}: faltan campos {', '.join(sorted(missing))}")
        for field in required:
            check(isinstance(control[field], str) and control[field].strip(), f"{control['id']}: {field} no es válido")

        control.setdefault("implementation", "")
        control.setdefault("references", [])
        control.setdefault("stride", [])
        check(isinstance(control["implementation"], str), f"{control['id']}: implementation debe ser texto")
        check(isinstance(control["references"], list), f"{control['id']}: references debe ser una lista")
        check(isinstance(control["stride"], list), f"{control['id']}: stride debe ser una lista")
        check(all(isinstance(value, str) for value in control["stride"]), f"STRIDE inválido en {control['id']}")
        check(set(control["stride"]) <= set(STRIDE), f"STRIDE inválido en {control['id']}")

    ids = [control["id"] for control in controls]
    check(len(ids) == len(set(ids)), "los IDs de controles deben ser únicos")
    return controls


def validate_architecture(data: dict) -> None:
    components = data["components"]
    flows = data["data_flows"]
    check(isinstance(components, list) and components, "no hay componentes")
    check(isinstance(flows, list), "data_flows debe ser una lista")

    component_ids = unique_ids(components, "componentes")
    for component in components:
        check(component["name"], f"{component['id']}: falta name")
        check(component["type"] in TYPES, f"{component['id']}: type debe ser uno de {TYPES}")

    flow_ids = unique_ids(flows, "flujos")
    check(not component_ids & flow_ids, "un flujo usa el ID de un componente")
    for flow in flows:
        check(
            flow["source"] in component_ids and flow["target"] in component_ids,
            f"{flow['id']}: source o target no existe",
        )


def validate_threats(data: dict, architecture: dict) -> None:
    threats = data["threats"]
    check(isinstance(threats, list) and threats, "no hay amenazas")
    unique_ids(threats, "amenazas")

    elements = {item["id"] for item in architecture["components"] + architecture["data_flows"]}
    for threat in threats:
        check(threat["element_id"] in elements, f"{threat['id']}: element_id no existe")
        check(threat["stride"] in STRIDE, f"{threat['id']}: categoría STRIDE inválida")
        check(threat["title"] and threat["description"], f"{threat['id']}: faltan title o description")


def validate_mappings(data: dict, threats: list[dict], controls: list[dict]) -> None:
    mappings = data["mappings"]
    check(isinstance(mappings, list), "mappings debe ser una lista")

    threat_ids = {threat["id"] for threat in threats}
    control_ids = {control["id"] for control in controls}
    mapped = [mapping["threat_id"] for mapping in mappings]
    check(len(mapped) == len(set(mapped)), "hay amenazas mapeadas más de una vez")
    check(set(mapped) == threat_ids, "debe haber exactamente un mapeo por amenaza")

    for mapping in mappings:
        ids = mapping["control_ids"]
        check(isinstance(ids, list) and 1 <= len(ids) <= 3, f"{mapping['threat_id']}: se esperan entre 1 y 3 controles")
        unknown = sorted(set(ids) - control_ids)
        check(not unknown, f"{mapping['threat_id']}: control inexistente: {', '.join(unknown)}")
        check(mapping["recommendation"], f"{mapping['threat_id']}: falta recommendation")


# Los cuatro procesos pedidos en el ejercicio.
def agent_extract_components(llm: LLM, image: Path) -> dict:
    return llm.chat_json(PROMPT_ARCHITECTURE, validate_architecture, image)


def agent_identify_threats(llm: LLM, architecture: dict) -> list[dict]:
    prompt = f"{PROMPT_THREATS}\n\nArquitectura:\n{dump(architecture)}"
    data = llm.chat_json(prompt, lambda value: validate_threats(value, architecture))
    return data["threats"]


def agent_map_controls(llm: LLM, threats: list[dict], controls: list[dict]) -> list[dict]:
    compact_controls = []
    for control in controls:
        compact = {key: control[key] for key in ("id", "category", "name", "description")}
        if control["stride"]:
            compact["stride"] = control["stride"]
        compact_controls.append(compact)
    prompt = (
        f"{PROMPT_MAPPINGS}\n\nAmenazas:\n{dump(threats)}"
        f"\n\nCatálogo de controles:\n{dump(compact_controls)}"
    )
    data = llm.chat_json(prompt, lambda value: validate_mappings(value, threats, controls))
    return data["mappings"]


def table(headers: list[str], rows: list[list]) -> str:
    def cell(value) -> str:
        return " ".join(str(value or "-").split()).replace("|", "\\|")

    lines = ["| " + " | ".join(headers) + " |", "|" + " --- |" * len(headers)]
    lines += ["| " + " | ".join(cell(value) for value in row) + " |" for row in rows]
    return "\n".join(lines)


def agent_generate_report(
    architecture: dict,
    threats: list[dict],
    mappings: list[dict],
    controls: list[dict],
    image_name: str,
    catalog_name: str,
) -> str:
    """Genera el informe final desde los resultados ya validados."""
    components = {component["id"]: component for component in architecture["components"]}
    names = {key: value["name"] for key, value in components.items()}
    for flow in architecture["data_flows"]:
        names[flow["id"]] = f"{names[flow['source']]} → {names[flow['target']]}"

    mapping_by_threat = {mapping["threat_id"]: mapping for mapping in mappings}
    sections = [
        "# Modelo de amenazas",
        f"**Catálogo de controles:** `{catalog_name}`",
        "## 1. Arquitectura analizada",
        f"![Diagrama de arquitectura]({image_name})",
        table(
            ["ID", "Componente", "Tipo", "Descripción"],
            [[c["id"], c["name"], c["type"], c.get("description", "")] for c in architecture["components"]],
        ),
    ]

    if architecture["data_flows"]:
        sections += [
            "### Flujos de datos",
            table(
                ["ID", "Origen", "Destino", "Protocolo", "Descripción"],
                [
                    [
                        flow["id"],
                        names[flow["source"]],
                        names[flow["target"]],
                        flow.get("protocol", ""),
                        flow.get("description", ""),
                    ]
                    for flow in architecture["data_flows"]
                ],
            ),
        ]

    sections += [
        "## 2. Amenazas identificadas",
        table(
            ["ID", "Elemento", "STRIDE", "Amenaza", "Descripción"],
            [[t["id"], names[t["element_id"]], t["stride"], t["title"], t["description"]] for t in threats],
        ),
        "## 3. Controles y recomendaciones",
        table(
            ["Amenaza", "Controles", "Recomendación"],
            [
                [
                    threat["id"],
                    ", ".join(mapping_by_threat[threat["id"]]["control_ids"]),
                    mapping_by_threat[threat["id"]]["recommendation"],
                ]
                for threat in threats
            ],
        ),
        "## 4. Catálogo de controles de seguridad",
        table(
            ["ID", "Categoría", "Control", "Descripción", "Implementación"],
            [[c["id"], c["category"], c["name"], c["description"], c["implementation"]] for c in controls],
        ),
        "## 5. Limitaciones",
        (
            "El análisis se basa en la información visible en el diagrama y en resultados generados por un LLM. "
            "Debe revisarse manualmente antes de utilizarse como decisión de seguridad definitiva."
        ),
    ]
    return "\n\n".join(sections) + "\n"


def save_json(path: Path, value) -> None:
    path.write_text(dump(value) + "\n", encoding="utf-8")


def run_pipeline(
    llm: LLM,
    image: Path,
    out_dir: Path,
    controls_file: Path = DEFAULT_CONTROLS_FILE,
) -> Path:
    """Ejecuta los cuatro procesos y devuelve la ruta del informe generado."""
    controls = load_controls(controls_file)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("[1/4] Extracción de componentes")
    architecture = agent_extract_components(llm, image)
    save_json(out_dir / "1_components.json", architecture)

    print("[2/4] Identificación de amenazas")
    threats = agent_identify_threats(llm, architecture)
    save_json(out_dir / "2_threats.json", threats)

    print("[3/4] Mapeo a controles")
    mappings = agent_map_controls(llm, threats, controls)
    save_json(out_dir / "3_mappings.json", mappings)

    print("[4/4] Generación del informe")
    image_link = Path(os.path.relpath(image.resolve(), out_dir.resolve())).as_posix()
    report = agent_generate_report(architecture, threats, mappings, controls, image_link, controls_file.name)
    report_path = out_dir / "4_threat_model.md"
    report_path.write_text(report, encoding="utf-8")
    return report_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Genera un modelo de amenazas desde un diagrama.")
    parser.add_argument("image", type=Path, help="diagrama PNG, JPG o WebP")
    parser.add_argument("--model", default=os.getenv("LLM_MODEL"), help="modelo con visión; también LLM_MODEL")
    parser.add_argument("--base-url", default=os.getenv("LLM_BASE_URL", BASE_URL), help="también LLM_BASE_URL")
    parser.add_argument("--api-key", default=os.getenv("LLM_API_KEY", "ollama"), help="también LLM_API_KEY")
    parser.add_argument(
        "--controls",
        type=Path,
        default=DEFAULT_CONTROLS_FILE,
        help="catálogo JSON; por defecto controls/m6t1.json",
    )
    parser.add_argument("--out-dir", type=Path, help="por defecto output/<nombre-diagrama>")
    args = parser.parse_args(argv)

    if not args.image.is_file():
        parser.error(f"no existe el diagrama {args.image}")
    if not args.model:
        parser.error("indica --model o define LLM_MODEL")
    if not args.controls.is_file():
        parser.error(f"no existe el catálogo de controles {args.controls}")

    out_dir = args.out_dir or Path("output") / args.image.stem
    try:
        report = run_pipeline(
            LLM(args.base_url, args.api_key, args.model),
            args.image,
            out_dir,
            args.controls,
        )
        print(f"Informe generado: {report}")
        return 0
    except (LLMError, ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
