#!/usr/bin/env python3
"""Run the patch policy evaluator in mock mode by default."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_SAMPLE = ROOT_DIR / "tests" / "data" / "sample-ai-review.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="review package JSON")
    parser.add_argument("--output", required=True, help="model output JSON")
    parser.add_argument(
        "--mode",
        choices=("mock", "external"),
        default=os.environ.get("AI_POLICY_EVAL_MODE", "mock"),
        help="evaluation mode; mock is the default for the POC",
    )
    parser.add_argument(
        "--mock-response",
        default=str(DEFAULT_SAMPLE),
        help="path to mock JSON used in mock mode",
    )
    parser.add_argument(
        "--external-cmd",
        default=os.environ.get("AI_POLICY_EVAL_CMD"),
        help="future extension point; command must read the input path as its final argument and print JSON to stdout",
    )
    return parser.parse_args()


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def run_external(command: str, input_path: str) -> object:
    result = subprocess.run(
        shlex.split(command) + [input_path],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def main() -> int:
    args = parse_args()
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if args.mode == "mock":
        model_output = load_json(Path(args.mock_response))
    else:
        if not args.external_cmd:
            raise SystemExit(
                "external mode requires --external-cmd; keep mock mode for the default POC path"
            )
        model_output = run_external(args.external_cmd, args.input)

    output_path.write_text(json.dumps(model_output, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
