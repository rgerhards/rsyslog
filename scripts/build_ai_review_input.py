#!/usr/bin/env python3
"""Build a deterministic review package from a git diff."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path


DEFAULT_UNIFIED_CONTEXT = 40
ROOT_DIR = Path(__file__).resolve().parents[1]
POLICY_CATALOG = ROOT_DIR / "ai-policy" / "policy-catalog.yaml"
EVALUATOR_PROMPT = ROOT_DIR / "ai-policy" / "prompts" / "check_patch_policy.md"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", help="base ref or sha")
    parser.add_argument("--head", help="head ref or sha")
    parser.add_argument("--output", required=True, help="output review package path")
    parser.add_argument(
        "--unified",
        type=int,
        default=DEFAULT_UNIFIED_CONTEXT,
        help="unified diff context lines",
    )
    return parser.parse_args()


def resolve_ref(cli_value: str | None, env_names: tuple[str, ...], default: str | None) -> str:
    if cli_value:
        return cli_value
    for env_name in env_names:
        value = os.environ.get(env_name)
        if value:
            return value
    if default is None:
        raise SystemExit(f"missing required ref; checked {', '.join(env_names)}")
    return default


def run_git(args: list[str]) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT_DIR,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def count_patch_lines(diff_text: str) -> int:
    count = 0
    for line in diff_text.splitlines():
        if not line:
            continue
        if line.startswith(("+++", "---", "@@", "diff ", "index ")):
            continue
        if line[0] in {"+", "-"}:
            count += 1
    return count


def classify_size(patch_line_count: int) -> tuple[str, str]:
    if patch_line_count > 4000:
        return (
            "large",
            "Patch is too large for reliable POC AI review. The workflow will skip evaluation.",
        )
    if patch_line_count > 1500:
        return (
            "medium",
            "Patch size reduces confidence in the POC AI review result.",
        )
    return ("small", "")


def main() -> int:
    args = parse_args()
    base = resolve_ref(args.base, ("AI_REVIEW_BASE", "GITHUB_BASE_SHA"), "HEAD")
    head = resolve_ref(args.head, ("AI_REVIEW_HEAD", "GITHUB_HEAD_SHA"), "HEAD")

    diff_text = run_git(["diff", f"--unified={args.unified}", base, head])
    changed_files = [
        line for line in run_git(["diff", "--name-only", base, head]).splitlines() if line
    ]
    patch_line_count = count_patch_lines(diff_text)
    size_class, caution = classify_size(patch_line_count)

    package = {
        "base": base,
        "head": head,
        "changed_files": changed_files,
        "patch_line_count": patch_line_count,
        "size_class": size_class,
        "caution": caution,
        "diff": diff_text,
        "policy_catalog": POLICY_CATALOG.read_text(encoding="utf-8"),
        "evaluator_prompt": EVALUATOR_PROMPT.read_text(encoding="utf-8"),
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(package, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
