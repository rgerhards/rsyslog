# AI Patch Policy Review POC

This proof of concept adds a non-blocking GitHub Actions review pass that checks
patches against a very small repository policy catalog. It is intentionally
deterministic, mock-first, and easy to debug.

## Purpose

The workflow builds a review package from the pull request diff, classifies the
patch by changed patch lines, and only runs the evaluator for small and medium
pull requests. Large pull requests are skipped with an explicit summary because
the POC should not pretend to give reliable automated guidance for oversized
patches.

What the POC does:

- counts added and removed diff lines while excluding diff metadata lines
- packages the diff, changed file list, policy catalog, and evaluator prompt
- runs a mock evaluator by default
- normalizes the evaluator JSON into markdown and machine-readable summary files
- writes a workflow summary and uploads artifacts

What the POC does not do:

- block merges based on score
- post pull request comments
- auto-fix anything
- require live model credentials

## Size thresholds

- `small`: up to 1500 changed patch lines, normal review
- `medium`: 1501 to 4000 changed patch lines, review with a confidence caution
- `large`: more than 4000 changed patch lines, skip AI review and explain why

Patch lines mean added plus removed lines from the unified diff. Diff metadata
such as file headers, hunk headers, and index lines are ignored.

## Mock mode

`scripts/run_ai_policy_eval.py` defaults to `mock` mode. In that mode it copies
[`tests/data/sample-ai-review.json`](/home/rger/proj/rsyslog3/tests/data/sample-ai-review.json)
to the requested output path so the full workflow can run without any model
credentials.

## Scoring

`scripts/score_ai_review.py` trusts the evaluator JSON when present, but it also
normalizes the structure and derives a normalized rating from `overall_score`:

- `85..100`: `good`
- `70..84`: `acceptable`
- `50..69`: `mixed`
- below `50`: `poor`

For medium patches the summary adds a caution note. For large patches the scorer
does not score the review and emits a skip summary instead.

## Replacing mock mode later

The future integration point is isolated in `scripts/run_ai_policy_eval.py`.

To replace mock mode with a real evaluator:

1. Keep `scripts/build_ai_review_input.py` and `scripts/score_ai_review.py`
   unchanged so the package and summary formats stay stable.
2. Implement an external command that accepts the review package path as its
   final argument and prints strict JSON matching the documented schema to
   stdout.
3. Update the workflow step to call:

   ```bash
   python3 scripts/run_ai_policy_eval.py \
     --mode external \
     --external-cmd "path/to/real-evaluator --flag value" \
     --input out/review-package.json \
     --output out/model-output.json
   ```

4. Store any credentials needed by the external evaluator in GitHub Actions
   secrets and inject them only into that step.

This keeps the real model dependency isolated to one script and one workflow
step.
