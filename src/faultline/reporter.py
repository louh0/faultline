from __future__ import annotations

import json
from collections.abc import Sequence

from faultline.models import (
    CaptureSessionSummary,
    HttpExchange,
    ReplayReport,
    Severity,
)


def format_sessions_table(sessions: Sequence[CaptureSessionSummary]) -> str:
    if not sessions:
        return "No capture sessions found in store."

    header = (
        f"{'SESSION':<22} {'EXCHANGES':>10} {'SHAPES':>8} "
        f"{'ERRORS':>8} {'AVG_LATENCY':>13} {'LAST_CAPTURED':<25}"
    )
    sep = "-" * len(header)
    lines = [header, sep]
    for s in sessions:
        lines.append(
            f"{s.session:<22} {s.exchange_count:>10} {s.unique_fingerprints:>8} "
            f"{s.error_count:>8} {s.avg_latency_ms:>11.2f}ms {s.last_captured_at[:24]:<25}"
        )
    return "\n".join(lines)


def format_exchanges_table(exchanges: Sequence[HttpExchange]) -> str:
    if not exchanges:
        return "No exchanges matched filter criteria."

    header = (
        f"{'ID':<14} {'METHOD':<7} {'STATUS':>6} {'LATENCY':>10} "
        f"{'FINGERPRINT':<18} {'PATH'}"
    )
    sep = "-" * 84
    lines = [header, sep]
    for ex in exchanges:
        lines.append(
            f"{ex.exchange_id:<14} {ex.request.method:<7} {ex.response.status_code:>6} "
            f"{ex.response.latency_ms:>8.2f}ms {ex.fingerprint:<18} {ex.request.path}"
        )
    return "\n".join(lines)


def format_replay_report(report: ReplayReport, output_format: str = "text") -> str:
    fmt = output_format.lower()
    if fmt == "json":
        return json.dumps(report.to_dict(), indent=2, sort_keys=True)
    if fmt == "markdown":
        return _format_replay_markdown(report)
    return _format_replay_text(report)


def _format_replay_text(report: ReplayReport) -> str:
    verdict = "PASS" if report.passed else "FAIL (breaking contract drift)"
    lines: list[str] = [
        f"Faultline Contract Report :: session={report.session}",
        "=" * 74,
        f"Target   : {report.target_url}",
        f"Verdict  : {verdict}",
        f"Exchanges: {report.total_exchanges} total | "
        f"{report.passed_count} passed | {report.breaking_count} breaking | "
        f"{report.warning_count} warnings",
        (
            f"Latency  : p50/p95 baseline {report.baseline_latency.p50_ms:.2f}ms / "
            f"{report.baseline_latency.p95_ms:.2f}ms -> "
            f"candidate {report.candidate_latency.p50_ms:.2f}ms / "
            f"{report.candidate_latency.p95_ms:.2f}ms "
            f"(p95 delta: {report.p95_regression_ms:+.2f}ms)"
        ),
        "-" * 74,
    ]

    for comp in report.comparisons:
        status_badge = "PASS"
        if comp.has_breaking_changes:
            status_badge = "BREAK"
        elif comp.has_warnings:
            status_badge = "WARN"

        cand_code = str(comp.candidate_status) if comp.candidate_status is not None else "ERR"
        lines.append(
            f"[{status_badge:<5}] {comp.exchange_id}  {comp.method:<6} {comp.path:<34} "
            f"{comp.baseline_status}->{cand_code}  "
            f"({comp.baseline_latency_ms:.1f}ms -> {comp.candidate_latency_ms:.1f}ms)"
        )
        for v in comp.violations:
            sev_tag = v.severity.value.upper()
            lines.append(
                f"        - [{sev_tag}] {v.kind.value} at {v.path}: {v.message}"
            )
    return "\n".join(lines)


def _format_replay_markdown(report: ReplayReport) -> str:
    verdict = "PASSED" if report.passed else "FAILED"
    lines: list[str] = [
        f"## Faultline Contract Report (`{report.session}`) - **{verdict}**",
        "",
        f"- **Target**: `{report.target_url}`",
        f"- **Exchanges**: `{report.total_exchanges}` total (`{report.passed_count}` passed, "
        f"`{report.breaking_count}` breaking, `{report.warning_count}` warnings)",
        f"- **p95 Latency**: `{report.baseline_latency.p95_ms:.2f}ms` baseline vs "
        f"`{report.candidate_latency.p95_ms:.2f}ms` candidate (`{report.p95_regression_ms:+.2f}ms`)",
        "",
        "| Exchange | Endpoint | Status | Latency Delta | Findings |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]
    for comp in report.comparisons:
        cand_code = str(comp.candidate_status) if comp.candidate_status is not None else "ERR"
        breaking_n = sum(1 for v in comp.violations if v.severity == Severity.BREAKING)
        warn_n = sum(1 for v in comp.violations if v.severity == Severity.WARNING)
        summary = "Clean"
        if breaking_n or warn_n:
            summary = f"{breaking_n} breaking, {warn_n} warnings"
        lines.append(
            f"| `{comp.exchange_id}` | `{comp.method} {comp.path}` | "
            f"`{comp.baseline_status} -> {cand_code}` | `{comp.latency_delta_ms:+.1f}ms` | {summary} |"
        )
    return "\n".join(lines)
