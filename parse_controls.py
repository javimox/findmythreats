#!/usr/bin/env python3
"""Convert external control catalogs to the FindMyThreats JSON format.

Currently supports NIST SP 800-53 Rev. 5 OSCAL JSON catalogs.
"""

import argparse
import json
import re
import sys
from pathlib import Path

INSERT_PARAM = re.compile(
    r"\{\{\s*insert\s*:\s*param\s*,\s*([^\s{}]+)\s*\}\}", re.IGNORECASE
)
INSERT_ANY = re.compile(r"\{\{\s*insert\s*:[^{}]*\}\}", re.IGNORECASE)


def _prop(item: dict, name: str) -> str:
    for prop in item.get("props", []):
        if prop.get("name") == name and isinstance(prop.get("value"), str):
            return prop["value"]
    return ""


def _parameter_map(*param_groups: list[dict]) -> dict[str, str]:
    values: dict[str, str] = {}
    for params in param_groups:
        for param in params or []:
            param_id = param.get("id")
            if not isinstance(param_id, str) or not param_id:
                continue

            assigned = param.get("values")
            if isinstance(assigned, list) and assigned and all(isinstance(v, str) for v in assigned):
                values[param_id] = ", ".join(v.strip() for v in assigned)
                continue

            label = param.get("label")
            if isinstance(label, str) and label.strip():
                values[param_id] = f"[{label.strip()}]"
                continue

            selection = param.get("select")
            if isinstance(selection, dict):
                choices = selection.get("choice")
                if isinstance(choices, list) and choices and all(isinstance(v, str) for v in choices):
                    prefix = "one or more of" if selection.get("how-many") == "one-or-more" else "one of"
                    values[param_id] = f"[{prefix}: {'; '.join(choice.strip() for choice in choices)}]"
    return values


def _render(text: str, params: dict[str, str]) -> str:
    def replace(match: re.Match) -> str:
        param_id = match.group(1)
        if param_id not in params:
            raise ValueError(f"unresolved NIST parameter: {param_id}")
        return params[param_id]

    rendered = text
    # A parameter value can itself contain another OSCAL parameter insert.
    for _ in range(len(params) + 1):
        rendered, count = INSERT_PARAM.subn(replace, rendered)
        if count == 0:
            break

    leftover = INSERT_ANY.search(rendered)
    if leftover:
        raise ValueError(f"unsupported OSCAL insert expression: {leftover.group(0)}")
    return " ".join(rendered.split())


def _part_text(part: dict, params: dict[str, str]) -> str:
    chunks = []
    prose = part.get("prose")
    if isinstance(prose, str) and prose.strip():
        chunks.append(_render(prose, params))
    for child in part.get("parts", []):
        chunks.append(_part_text(child, params))
    return " ".join(chunk for chunk in chunks if chunk)


def _named_part(control: dict, name: str, params: dict[str, str]) -> str:
    chunks = [
        _part_text(part, params)
        for part in control.get("parts", [])
        if part.get("name") == name
    ]
    return " ".join(chunk for chunk in chunks if chunk)


def parse_nist(source: Path, families: set[str]) -> list[dict]:
    """Convert selected NIST SP 800-53 Rev. 5 base-control families."""
    data = json.loads(source.read_text(encoding="utf-8"))
    catalog = data.get("catalog")
    if not isinstance(catalog, dict):
        raise ValueError("source is not an OSCAL catalog")

    groups = catalog.get("groups")
    if not isinstance(groups, list):
        raise ValueError("OSCAL catalog has no groups")

    available = {str(group.get("id", "")).upper() for group in groups if group.get("id")}
    unknown = sorted(families - available)
    if unknown:
        raise ValueError(f"unknown NIST families: {', '.join(unknown)}")

    result = []
    catalog_params = catalog.get("params", [])
    for group in groups:
        family = str(group.get("id", "")).upper()
        if family not in families:
            continue

        category = str(group.get("title", family)).strip() or family
        group_params = group.get("params", [])

        # Only direct, active controls are converted. Nested controls are enhancements.
        for control in group.get("controls", []):
            if _prop(control, "status").strip().lower() == "withdrawn":
                continue

            params = _parameter_map(catalog_params, group_params, control.get("params", []))
            control_id = str(control.get("id", "")).upper()
            title = str(control.get("title", "")).strip()
            if not control_id or not title:
                raise ValueError(f"invalid control in NIST family {family}")

            description = _named_part(control, "statement", params)
            if not description:
                raise ValueError(f"{control_id}: missing statement")

            result.append(
                {
                    "id": control_id,
                    "category": category,
                    "name": title,
                    "description": description,
                    "implementation": _named_part(control, "guidance", params),
                    "references": [f"NIST SP 800-53 Rev. 5, {control_id}"],
                    "stride": [],
                }
            )

    if not result:
        raise ValueError("no controls found for the selected families")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert control catalogs for FindMyThreats.")
    parser.add_argument("format", choices=("nist",), help="source catalog format")
    parser.add_argument("source", type=Path, help="source catalog file")
    parser.add_argument("--families", required=True, help="comma-separated NIST families, e.g. AC,IA,SC")
    parser.add_argument("--output", type=Path, required=True, help="output FindMyThreats JSON file")
    args = parser.parse_args(argv)

    if not args.source.is_file():
        parser.error(f"source file not found: {args.source}")

    families = {value.strip().upper() for value in args.families.split(",") if value.strip()}
    if not families:
        parser.error("--families must contain at least one family")

    try:
        controls = parse_nist(args.source, families)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(controls, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"Wrote {len(controls)} controls to {args.output}")
        return 0
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
