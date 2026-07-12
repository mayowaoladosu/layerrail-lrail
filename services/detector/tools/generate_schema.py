"""Generate the detector JSON Schema from its strict Pydantic contract."""

from __future__ import annotations

import json
from pathlib import Path

from lrail_detector.models import DetectionResult

ROOT = Path(__file__).resolve().parents[3]
OUTPUT = ROOT / "contracts/jsonschema/detector/detection-result.schema.json"


def main() -> None:
    """Write deterministic indented JSON with one trailing newline."""
    schema = DetectionResult.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = "https://contracts.lrail.dev/detector/detection-result.schema.json"
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(f"{json.dumps(schema, indent=2, sort_keys=True)}\n", encoding="utf-8")


if __name__ == "__main__":
    main()
