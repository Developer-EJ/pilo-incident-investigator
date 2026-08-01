"""Run the deterministic offline evaluation and emit redacted reports."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from pilo_incident_investigator.evaluation.loader import load_manifest  # noqa: E402
from pilo_incident_investigator.evaluation.report import (  # noqa: E402
    OFFLINE_MODEL_ID,
    LiveEvaluationUnavailable,
    aggregate_payload,
    build_offline_report,
    write_reserved_report,
)
from pilo_incident_investigator.evaluation.report import (  # noqa: E402
    reserve_report_slot as reserve_report_slot,
)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.live_bedrock and not args.acknowledge_cost:
        parser.error("--live-bedrock requires --acknowledge-cost")
    if args.live_bedrock and (not args.model_id or not args.model_id.strip()):
        parser.error("--live-bedrock requires --model-id")
    if args.live_bedrock and (
        args.input_cost_per_million is None or args.output_cost_per_million is None
    ):
        parser.error("--live-bedrock requires explicit input and output token rates")
    if args.live_bedrock:
        raise LiveEvaluationUnavailable(
            "live Bedrock evaluation is not implemented safely: no strict production "
            "investigation and HandoffOutput adapter is available"
        )

    reports_dir = args.reports_dir.resolve()
    reservation = reserve_report_slot(reports_dir, _utc_now())
    try:
        report = build_offline_report(
            load_manifest(ROOT / "fixtures" / "eval" / "manifest.yaml"),
            generated_at=reservation.generated_at,
            git_commit=_git_commit(),
            model_id=OFFLINE_MODEL_ID,
            input_cost_per_million=Decimal("0"),
            output_cost_per_million=Decimal("0"),
        )
        write_reserved_report(report, reservation)
    except Exception:
        reservation.release()
        raise
    print(json.dumps(aggregate_payload(report), ensure_ascii=False, sort_keys=True))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live-bedrock", action="store_true")
    parser.add_argument("--model-id")
    parser.add_argument("--input-cost-per-million", type=_token_rate)
    parser.add_argument("--output-cost-per-million", type=_token_rate)
    parser.add_argument("--acknowledge-cost", action="store_true")
    parser.add_argument("--reports-dir", type=Path, default=ROOT / "reports")
    return parser


def _token_rate(value: str) -> Decimal:
    try:
        rate = Decimal(value)
    except InvalidOperation:
        raise argparse.ArgumentTypeError("token rate must be a decimal") from None
    if not rate.is_finite() or rate < 0:
        raise argparse.ArgumentTypeError("token rate must be finite and non-negative")
    return rate


def _git_commit() -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    commit = completed.stdout.strip()
    if not commit:
        raise RuntimeError("git commit could not be determined")
    return commit


def _utc_now() -> datetime:
    return datetime.now(UTC)


if __name__ == "__main__":
    raise SystemExit(main())
