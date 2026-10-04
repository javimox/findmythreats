# FindMyThreats

AI-assisted threat modeling from architecture diagrams.

FindMyThreats analyzes architecture diagrams with a multimodal LLM and turns them into structured threat models.

The process is divided into four steps:

1. extract components and data flows;
2. identify threats using STRIDE;
3. map threats to a fixed security-control catalog;
4. generate a final threat-model report.

An LLM with vision capabilities (VLM) is required for processing the diagrams.  
FindMyThreats talks to any endpoint that exposes the Chat Completions API:

  * Cloud providers such as Anthropic or OpenAI
  * Local servers such as Ollama, LM Studio, or vLLM.

## Usage

The core uses only the Python 3.11+ standard library. The optional web interface adds no external dependencies.

### Web interface

```bash
python web.py
```

Open `http://127.0.0.1:8000`. The web interface lets you:

- configure the LLM URL, model, and optional API key;
- drag and drop or select a PNG, JPG, or WebP diagram, and preview it;
- see how long the analysis took;
- download each generated artifact;
- read the final report directly in the browser.

The API key is used only for the request and is **never written to disk**. The server listens only on `127.0.0.1`: it calls whatever LLM URL you give it, so it should not be exposed to a network. The report is rendered from escaped content in a sandboxed `iframe`, under a restrictive Content Security Policy.

### Command line

FindMyThreats can also be used from the command line, making it easy to integrate into CI/CD pipelines.

```bash
python findmythreats.py input/architecture.png \
  --base-url http://localhost:11434/v1 \
  --model model-name
```

If the provider requires an API key:

```bash
python findmythreats.py input/architecture.png \
  --base-url https://service.example/v1 \
  --model model-name \
  --api-key '...'
```

`LLM_BASE_URL`, `LLM_MODEL`, and `LLM_API_KEY` can also be provided as environment variables.

## Generated files

Every analysis creates its own directory under `output/`.  
CLI supports `--out-dir` to change the output directory.

Each analysis generates:

| File | Content |
|---|---|
| `1_components.json` | components and data flows extracted from the diagram |
| `2_threats.json` | identified STRIDE threats |
| `3_mappings.json` | mapping between threats and security controls |
| `4_threat_model.md` | final threat-model report |

Web runs also keep the uploaded diagram and a `4_threat_model.html` copy of the report for the browser.

## Security controls

`controls/m6t1.json` is the default catalog. It defines 15 controls across five categories, three per category:

- Authentication
- Authorization
- Data in transit
- Logging
- Secrets management

Its identifiers are internal and do not correspond to a formal security standard.

Normative security standards can also be used with `--controls`, provided they are converted to the same JSON schema and saved as `controls.json`.

Each control must provide:

- `id`
- `category`
- `name`
- `description`

`implementation`, `references`, and `stride` are optional.

## Design

- Four simple processing stages
- Structured JSON validated between stages
- STRIDE is applied according to element type
- Missing protections are treated as unknown rather than assumed absent
- The final Markdown report is built deterministically from the validated results
- Threat-to-control mapping is restricted to the selected control catalog

## Project structure

```text
findmythreats/
├── findmythreats.py
├── controls/
│   └── m6t1.json
├── web.py
├── web.html
├── input/
├── output/
└── tests/
    └── test_findmythreats.py
```

`findmythreats.py` contains all the threat-modeling logic. `web.py` is only a presentation layer that reuses `run_pipeline()`.

## Tests

```bash
python -m unittest discover -s tests -v
```

Tests run without network access or a real LLM.

## Background

FindMyThreats was originally developed as part of a Master's program in AI Applied to Cybersecurity.
