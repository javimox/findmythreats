#!/usr/bin/env python3
"""FindMyThreats - Automated threat modeling from an architecture diagram.

Four stages: extraction, STRIDE threats, control mapping, and report generation.
Uses only the Python standard library.
"""

import argparse
import base64
import json
import mimetypes
import os
import re
import secrets
import shutil
import string
import sys
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

BASE_URL = "http://localhost:11434/v1"
ROOT = Path(__file__).resolve().parent
DEFAULT_CONTROLS_FILE = ROOT / "controls" / "m6t1_en.json"
TYPES = ("external entity", "process", "data store")
STRIDE = (
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
)
SYSTEM_PROMPT = (
    "You are a cybersecurity analyst specialized in threat modeling. "
    "Respond in English and follow the requested format exactly."
)

PROMPT_ARCHITECTURE = """\
Analyze the attached architecture diagram and extract its components and data flows.
Do not invent elements or protocols that are not represented.

Use only these component types: external entity, process, data store.
Return JSON only:
{
  "components": [{"id": "C1", "name": "...", "type": "process", "description": "..."}],
  "data_flows": [{"id": "F1", "source": "C1", "target": "C2", "protocol": "HTTPS", "description": "..."}]
}
IDs must be unique. source and target must refer to existing components.
If a value is not shown in the diagram, use an empty string.
"""

PROMPT_THREATS = """\
Identify security threats in the architecture by applying STRIDE to each element.

Guidance:
- external entity: Spoofing, Repudiation
- process: all six STRIDE categories
- data store: Tampering, Information Disclosure, Denial of Service
- data flow: Tampering, Information Disclosure, Denial of Service

Do not invent new elements. If a protection is not visible in the diagram, do not claim that
it is absent; phrase the threat conditionally.

Return JSON only:
{
  "threats": [{"id": "T1", "element_id": "C1 or F1", "stride": "Spoofing",
               "title": "short title", "description": "how the threat could materialize"}]
}
"""

PROMPT_MAPPINGS = """\
Map each threat to between one and three controls from the supplied catalog.
Use only control IDs from the catalog and generate exactly one entry per threat.

Return JSON only:
{
  "mappings": [{"threat_id": "T1", "control_ids": ["AUTH-001"],
                "recommendation": "specific action to reduce the threat"}]
}
"""


class LLMError(RuntimeError):
    pass


def dump(value) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2)


def extract_json(text: str) -> dict:
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end < start:
        raise ValueError("the response does not contain a JSON object")
    data = json.loads(text[start : end + 1])
    check(isinstance(data, dict), "the JSON response is not an object")
    return data


class LLM:
    """Minimal client for an OpenAI-compatible /chat/completions endpoint."""

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
            raise LLMError(f"Error calling the LLM: {exc}") from exc

        if not isinstance(result, str) or not result.strip():
            raise LLMError("The LLM returned an empty response")
        return result.strip()

    def chat_json(self, prompt: str, validate, image: Path | None = None) -> dict:
        """Request JSON and retry once if the response is invalid."""
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
                        f"\n\nThe previous response was invalid: {exc}. "
                        "Correct it and return only the requested JSON."
                    )
        raise LLMError(f"The model did not return a valid response: {last_error}")


def check(condition, message: str) -> None:
    if not condition:
        raise ValueError(message)


def unique_ids(items: list[dict], what: str) -> set[str]:
    ids = [item["id"] for item in items]
    check(len(ids) == len(set(ids)), f"duplicate {what} IDs")
    return set(ids)


def load_controls(path: Path = DEFAULT_CONTROLS_FILE) -> list[dict]:
    controls = json.loads(path.read_text(encoding="utf-8"))
    check(isinstance(controls, list) and controls, f"{path.name} must contain a list of controls")

    required = {"id", "category", "name", "description"}
    for index, control in enumerate(controls, start=1):
        check(isinstance(control, dict), f"control {index}: must be a JSON object")
        missing = required - control.keys()
        check(not missing, f"control {index}: missing fields {', '.join(sorted(missing))}")
        for field in required:
            check(isinstance(control[field], str) and control[field].strip(), f"{control['id']}: invalid {field}")

        control.setdefault("implementation", "")
        control.setdefault("references", [])
        control.setdefault("stride", [])
        check(isinstance(control["implementation"], str), f"{control['id']}: implementation must be text")
        check(isinstance(control["references"], list), f"{control['id']}: references must be a list")
        check(isinstance(control["stride"], list), f"{control['id']}: stride must be a list")
        check(all(isinstance(value, str) for value in control["stride"]), f"invalid STRIDE value in {control['id']}")
        check(set(control["stride"]) <= set(STRIDE), f"invalid STRIDE value in {control['id']}")

    ids = [control["id"] for control in controls]
    check(len(ids) == len(set(ids)), "control IDs must be unique")
    return controls


def validate_architecture(data: dict) -> None:
    components = data["components"]
    flows = data["data_flows"]
    check(isinstance(components, list) and components, "no components found")
    check(isinstance(flows, list), "data_flows must be a list")

    component_ids = unique_ids(components, "component")
    for component in components:
        check(component["name"], f"{component['id']}: missing name")
        check(component["type"] in TYPES, f"{component['id']}: type must be one of {TYPES}")

    flow_ids = unique_ids(flows, "data flow")
    check(not component_ids & flow_ids, "a data flow uses a component ID")
    for flow in flows:
        check(
            flow["source"] in component_ids and flow["target"] in component_ids,
            f"{flow['id']}: source or target does not exist",
        )


def validate_threats(data: dict, architecture: dict) -> None:
    threats = data["threats"]
    check(isinstance(threats, list) and threats, "no threats found")
    unique_ids(threats, "threat")

    elements = {item["id"] for item in architecture["components"] + architecture["data_flows"]}
    for threat in threats:
        check(threat["element_id"] in elements, f"{threat['id']}: element_id does not exist")
        check(threat["stride"] in STRIDE, f"{threat['id']}: invalid STRIDE category")
        check(threat["title"] and threat["description"], f"{threat['id']}: missing title or description")


def validate_mappings(data: dict, threats: list[dict], controls: list[dict]) -> None:
    mappings = data["mappings"]
    check(isinstance(mappings, list), "mappings must be a list")

    threat_ids = {threat["id"] for threat in threats}
    control_ids = {control["id"] for control in controls}
    mapped = [mapping["threat_id"] for mapping in mappings]
    check(len(mapped) == len(set(mapped)), "a threat is mapped more than once")
    check(set(mapped) == threat_ids, "there must be exactly one mapping per threat")

    for mapping in mappings:
        ids = mapping["control_ids"]
        check(isinstance(ids, list) and 1 <= len(ids) <= 3, f"{mapping['threat_id']}: expected between 1 and 3 controls")
        unknown = sorted(set(ids) - control_ids)
        check(not unknown, f"{mapping['threat_id']}: unknown control ID: {', '.join(unknown)}")
        check(mapping["recommendation"], f"{mapping['threat_id']}: missing recommendation")


# The four processing stages.
def agent_extract_components(llm: LLM, image: Path) -> dict:
    return llm.chat_json(PROMPT_ARCHITECTURE, validate_architecture, image)


def agent_identify_threats(llm: LLM, architecture: dict) -> list[dict]:
    prompt = f"{PROMPT_THREATS}\n\nArchitecture:\n{dump(architecture)}"
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
        f"{PROMPT_MAPPINGS}\n\nThreats:\n{dump(threats)}"
        f"\n\nControl catalog:\n{dump(compact_controls)}"
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
    """Generate the final report from already validated results."""
    components = {component["id"]: component for component in architecture["components"]}
    names = {key: value["name"] for key, value in components.items()}
    for flow in architecture["data_flows"]:
        names[flow["id"]] = f"{names[flow['source']]} → {names[flow['target']]}"

    mapping_by_threat = {mapping["threat_id"]: mapping for mapping in mappings}
    sections = [
        "# Threat Model",
        f"**Control catalog:** `{catalog_name}`",
        "## 1. Analyzed Architecture",
        f"![Architecture diagram]({image_name})",
        table(
            ["ID", "Component", "Type", "Description"],
            [[c["id"], c["name"], c["type"], c.get("description", "")] for c in architecture["components"]],
        ),
    ]

    if architecture["data_flows"]:
        sections += [
            "### Data Flows",
            table(
                ["ID", "Source", "Target", "Protocol", "Description"],
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
        "## 2. Identified Threats",
        table(
            ["ID", "Element", "STRIDE", "Threat", "Description"],
            [[t["id"], names[t["element_id"]], t["stride"], t["title"], t["description"]] for t in threats],
        ),
        "## 3. Controls and Recommendations",
        table(
            ["Threat", "Controls", "Recommendation"],
            [
                [
                    threat["id"],
                    ", ".join(mapping_by_threat[threat["id"]]["control_ids"]),
                    mapping_by_threat[threat["id"]]["recommendation"],
                ]
                for threat in threats
            ],
        ),
        "## 4. Security Control Catalog",
        table(
            ["ID", "Category", "Control", "Description", "Implementation"],
            [[c["id"], c["category"], c["name"], c["description"], c["implementation"]] for c in controls],
        ),
        "## 5. Limitations",
        (
            "The analysis is based on information visible in the diagram and on LLM-generated results. "
            "It should be reviewed manually before being used to make final security decisions."
        ),
    ]
    return "\n\n".join(sections) + "\n"


def save_json(path: Path, value) -> None:
    path.write_text(dump(value) + "\n", encoding="utf-8")


def create_run_directory(image_name: str, output_root: Path) -> Path:
    """Create one timestamped output directory for an analysis run."""
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", Path(image_name).stem).strip(".-_") or "diagram"
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    alphabet = string.ascii_lowercase + string.digits
    while True:
        suffix = "".join(secrets.choice(alphabet) for _ in range(4))
        run_dir = output_root / f"{stem}-{timestamp}-{suffix}"
        try:
            run_dir.mkdir(parents=True, exist_ok=False)
        except FileExistsError:
            continue
        return run_dir


def run_pipeline(
    llm: LLM,
    image: Path,
    out_dir: Path,
    controls_file: Path = DEFAULT_CONTROLS_FILE,
    progress=None,
) -> Path:
    """Run the four stages and return the generated report path."""
    controls = load_controls(controls_file)
    out_dir.mkdir(parents=True, exist_ok=True)
    notify = progress or (lambda step, message: print(f"[{step}/4] {message}"))

    notify(1, "Extracting components")
    architecture = agent_extract_components(llm, image)
    save_json(out_dir / "1_components.json", architecture)

    notify(2, "Identifying threats")
    threats = agent_identify_threats(llm, architecture)
    save_json(out_dir / "2_threats.json", threats)

    notify(3, "Mapping security controls")
    mappings = agent_map_controls(llm, threats, controls)
    save_json(out_dir / "3_mappings.json", mappings)

    notify(4, "Generating report")
    image_link = Path(os.path.relpath(image.resolve(), out_dir.resolve())).as_posix()
    report = agent_generate_report(architecture, threats, mappings, controls, image_link, controls_file.name)
    report_path = out_dir / "4_threat_model.md"
    report_path.write_text(report, encoding="utf-8")
    return report_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a threat model from an architecture diagram.")
    parser.add_argument("image", type=Path, help="PNG, JPG, or WebP architecture diagram")
    parser.add_argument("--model", default=os.getenv("LLM_MODEL"), help="vision-capable model; also LLM_MODEL")
    parser.add_argument("--base-url", default=os.getenv("LLM_BASE_URL", BASE_URL), help="also LLM_BASE_URL")
    parser.add_argument("--api-key", default=os.getenv("LLM_API_KEY", "ollama"), help="also LLM_API_KEY")
    parser.add_argument(
        "--controls",
        type=Path,
        default=DEFAULT_CONTROLS_FILE,
        help="JSON control catalog; defaults to controls/m6t1_en.json",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        help="output root directory; defaults to output/",
    )
    args = parser.parse_args(argv)

    if not args.image.is_file():
        parser.error(f"diagram not found: {args.image}")
    if not args.model:
        parser.error("provide --model or set LLM_MODEL")
    if not args.controls.is_file():
        parser.error(f"control catalog not found: {args.controls}")

    output_root = args.out_dir or ROOT / "output"
    try:
        out_dir = create_run_directory(args.image.name, output_root)
        image = out_dir / f"diagram{args.image.suffix.lower()}"
        shutil.copy2(args.image, image)
        report = run_pipeline(
            LLM(args.base_url, args.api_key, args.model),
            image,
            out_dir,
            args.controls,
        )
        print(f"Report generated: {report}")
        return 0
    except (LLMError, ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
