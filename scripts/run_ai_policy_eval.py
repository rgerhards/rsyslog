#!/usr/bin/env python3
"""Run the patch policy evaluator using Gradient serverless inference."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_MODEL = os.environ.get("GRADIENT_MODEL_ID", "llama3.3-70b-instruct")
DEFAULT_ENDPOINT = os.environ.get(
    "GRADIENT_API_ENDPOINT", "https://inference.do-ai.run/v1/chat/completions"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="review package JSON")
    parser.add_argument("--output", required=True, help="model output JSON")
    parser.add_argument(
        "--mode",
        choices=("gradient", "external"),
        default=os.environ.get("AI_POLICY_EVAL_MODE", "gradient"),
        help="evaluation mode; gradient is the default for the live POC path",
    )
    parser.add_argument(
        "--gradient-model",
        default=DEFAULT_MODEL,
        help="Gradient model identifier",
    )
    parser.add_argument(
        "--gradient-endpoint",
        default=DEFAULT_ENDPOINT,
        help="Gradient chat completions endpoint",
    )
    parser.add_argument(
        "--external-cmd",
        default=os.environ.get("AI_POLICY_EVAL_CMD"),
        help="future extension point; command must read the input path as its final argument and print JSON to stdout",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=int(os.environ.get("AI_POLICY_EVAL_TIMEOUT", "120")),
        help="timeout in seconds for external evaluator mode",
    )
    return parser.parse_args()


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_gradient_endpoint(endpoint: str) -> str:
    parsed = urllib.parse.urlparse(endpoint)
    if parsed.scheme != "https":
        raise SystemExit("gradient endpoint must use https")
    if not parsed.netloc:
        raise SystemExit("gradient endpoint must include a host")
    return endpoint


def write_text(path: Path | None, content: str) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write_json(path: Path | None, payload: object) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def malformed_output_fallback(raw_content: str) -> dict[str, object]:
    snippet = " ".join(raw_content.strip().split())
    if len(snippet) > 240:
        snippet = snippet[:237] + "..."
    message = "Gradient returned malformed JSON output."
    if snippet:
        message = f"{message} Raw response excerpt: {snippet}"
    return {
        "summary": message,
        "metrics": {
            "ai_probability": 100,
            "policy_compliance": 0,
            "slop_score": 100,
        },
        "bad_patterns": [],
    }


def parse_model_json(raw_content: object) -> object:
    if not isinstance(raw_content, str):
        return malformed_output_fallback("")

    content = raw_content.strip()
    if not content:
        return malformed_output_fallback(content)

    if content.startswith("```"):
        lines = content.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        content = "\n".join(lines).strip()

    candidates = [content]
    for opener, closer in (("{", "}"), ("[", "]")):
        start = content.find(opener)
        end = content.rfind(closer)
        if start != -1 and end != -1 and end > start:
            candidates.append(content[start : end + 1])

    for candidate in candidates:
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue
    return malformed_output_fallback(raw_content)


def run_gradient(
    input_path: str,
    endpoint: str,
    model: str,
    timeout: int,
    raw_response_path: Path | None,
    raw_content_path: Path | None,
) -> object:
    api_key = os.environ.get("GRADIENT_API_KEY")
    if not api_key:
        raise SystemExit("gradient mode requires GRADIENT_API_KEY")
    endpoint = validate_gradient_endpoint(endpoint)

    package = load_json(Path(input_path))
    if not isinstance(package, dict):
        raise SystemExit("review package must be a JSON object")

    user_payload = {
        key: value for key, value in package.items() if key != "evaluator_prompt"
    }
    request_body = {
        "model": model,
        "messages": [
            {"role": "system", "content": str(package.get("evaluator_prompt", "")).strip()},
            {"role": "user", "content": json.dumps(user_payload, indent=2)},
        ],
        "temperature": 0,
        "max_completion_tokens": 512,
    }
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(request_body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(
            request,
            timeout=timeout,
        ) as response:  # nosec B310 - endpoint is prevalidated by validate_gradient_endpoint()
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"gradient request failed with HTTP {exc.code}: {body}") from exc
    write_json(raw_response_path, payload)

    try:
        content = payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise SystemExit("gradient response did not contain chat completion content") from exc
    write_text(raw_content_path, str(content))
    return parse_model_json(content)


def run_external(
    command: str,
    input_path: str,
    timeout: int,
    raw_content_path: Path | None,
) -> object:
    result = subprocess.run(
        shlex.split(command) + [input_path],
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    write_text(raw_content_path, result.stdout)
    return parse_model_json(result.stdout)


def main() -> int:
    args = parse_args()
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    raw_response_path = output_path.parent / "raw-gradient-response.json"
    raw_content_path = output_path.parent / "raw-model-content.txt"

    if args.mode == "gradient":
        model_output = run_gradient(
            args.input,
            args.gradient_endpoint,
            args.gradient_model,
            args.timeout,
            raw_response_path,
            raw_content_path,
        )
    else:
        if not args.external_cmd:
            raise SystemExit(
                "external mode requires --external-cmd"
            )
        model_output = run_external(
            args.external_cmd, args.input, args.timeout, raw_content_path
        )

    output_path.write_text(json.dumps(model_output, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
