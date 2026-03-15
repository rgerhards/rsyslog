#!/usr/bin/env python3
"""Normalize evaluator output into workflow-friendly markdown and JSON."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


VALID_STATUS = {"pass", "partial", "fail", "not_applicable"}
VALID_CONFIDENCE = {"high", "medium", "low"}
VALID_RATING = {"good", "acceptable", "mixed", "poor"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-input", required=True, help="review package JSON")
    parser.add_argument("--model-output", help="model output JSON")
    parser.add_argument("--summary-md", required=True, help="markdown summary output path")
    parser.add_argument("--summary-json", required=True, help="JSON summary output path")
    return parser.parse_args()


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def rating_from_score(score: int) -> str:
    if score >= 85:
        return "good"
    if score >= 70:
        return "acceptable"
    if score >= 50:
        return "mixed"
    return "poor"


def normalize_finding(item: object) -> dict[str, object]:
    if not isinstance(item, dict):
        return {
            "rule_id": "unknown",
            "status": "not_applicable",
            "confidence": "low",
            "file": "",
            "line": 0,
            "message": "Invalid finding entry.",
        }

    status = item.get("status")
    if status not in VALID_STATUS:
        status = "not_applicable"

    confidence = item.get("confidence")
    if confidence not in VALID_CONFIDENCE:
        confidence = "low"

    line = item.get("line")
    if not isinstance(line, int):
        line = 0

    return {
        "rule_id": str(item.get("rule_id", "unknown")),
        "status": status,
        "confidence": confidence,
        "file": str(item.get("file", "")),
        "line": line,
        "message": str(item.get("message", "")).strip(),
    }


def normalize_model_output(payload: object) -> dict[str, object]:
    if not isinstance(payload, dict):
        payload = {}

    summary = str(payload.get("summary", "No evaluator summary was provided.")).strip()
    findings = [normalize_finding(item) for item in payload.get("findings", [])]

    score = payload.get("score")
    if not isinstance(score, dict):
        score = {}

    overall_score = score.get("overall_score")
    if not isinstance(overall_score, int):
        overall_score = 0
    overall_score = max(0, min(100, overall_score))

    policy_score = score.get("policy_score")
    if not isinstance(policy_score, int):
        policy_score = overall_score
    policy_score = max(0, min(100, policy_score))

    style_fit_score = score.get("style_fit_score")
    if not isinstance(style_fit_score, int):
        style_fit_score = overall_score
    style_fit_score = max(0, min(100, style_fit_score))

    rating = score.get("rating")
    normalized_rating = rating_from_score(overall_score)
    if rating not in VALID_RATING:
        rating = normalized_rating

    return {
        "summary": summary,
        "findings": findings,
        "score": {
            "policy_score": policy_score,
            "style_fit_score": style_fit_score,
            "overall_score": overall_score,
            "rating": rating,
            "normalized_rating": normalized_rating,
        },
    }


def build_large_summary(review_input: dict[str, object]) -> dict[str, object]:
    message = str(
        review_input.get(
            "caution",
            "Patch is too large for reliable POC AI review. Evaluation was skipped.",
        )
    )
    return {
        "status": "skipped",
        "size_class": review_input.get("size_class", "large"),
        "patch_line_count": review_input.get("patch_line_count", 0),
        "changed_files": review_input.get("changed_files", []),
        "summary": message,
        "notes": [message],
        "model_summary": None,
        "findings": [],
        "score": None,
    }


def build_scored_summary(
    review_input: dict[str, object], model_output: dict[str, object]
) -> dict[str, object]:
    notes = []
    if review_input.get("size_class") == "medium":
        notes.append("Confidence is reduced because the patch falls in the medium-size review band.")

    return {
        "status": "reviewed",
        "size_class": review_input.get("size_class", "small"),
        "patch_line_count": review_input.get("patch_line_count", 0),
        "changed_files": review_input.get("changed_files", []),
        "summary": model_output["summary"],
        "notes": notes,
        "model_summary": model_output["summary"],
        "findings": model_output["findings"],
        "score": model_output["score"],
    }


def render_markdown(summary: dict[str, object]) -> str:
    lines = [
        "# AI Patch Policy Review",
        "",
        f"- Status: {summary['status']}",
        f"- Size class: {summary['size_class']}",
        f"- Patch lines: {summary['patch_line_count']}",
        f"- Changed files: {len(summary['changed_files'])}",
        "",
        summary["summary"],
        "",
    ]

    for note in summary.get("notes", []):
        lines.append(f"- Note: {note}")
    if summary.get("notes"):
        lines.append("")

    score = summary.get("score")
    if score:
        lines.extend(
            [
                "## Score",
                "",
                f"- Overall: {score['overall_score']} ({score['normalized_rating']})",
                f"- Reported rating: {score['rating']}",
                f"- Policy score: {score['policy_score']}",
                f"- Style fit score: {score['style_fit_score']}",
                "",
            ]
        )

    findings = summary.get("findings", [])
    if findings:
        lines.extend(["## Findings", ""])
        for finding in findings:
            location = finding["file"] or "(no file)"
            if finding["line"]:
                location = f"{location}:{finding['line']}"
            lines.append(
                f"- `{finding['rule_id']}` [{finding['status']}/{finding['confidence']}] {location} - {finding['message']}"
            )
    else:
        lines.extend(["## Findings", "", "- None."])

    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    review_input = load_json(Path(args.review_input))
    if not isinstance(review_input, dict):
        raise SystemExit("review input must be a JSON object")

    if review_input.get("size_class") == "large":
        summary = build_large_summary(review_input)
    else:
        if not args.model_output:
            raise SystemExit("model output is required for small and medium patches")
        normalized_output = normalize_model_output(load_json(Path(args.model_output)))
        summary = build_scored_summary(review_input, normalized_output)

    summary_md = Path(args.summary_md)
    summary_json = Path(args.summary_json)
    summary_md.parent.mkdir(parents=True, exist_ok=True)
    summary_json.parent.mkdir(parents=True, exist_ok=True)
    summary_md.write_text(render_markdown(summary), encoding="utf-8")
    summary_json.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
