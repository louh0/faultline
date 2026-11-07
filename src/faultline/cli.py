from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from faultline import __version__
from faultline.differ import DEFAULT_VOLATILE_PATHS, ContractDiffer, DiffConfig
from faultline.models import ExchangeComparison, HttpExchange, LatencyStats, ReplayReport
from faultline.proxy import RecordingReverseProxy
from faultline.redaction import RedactionPolicy, Redactor
from faultline.replay import ReplayEngine, ReplayOptions
from faultline.reporter import (
    format_exchanges_table,
    format_replay_report,
    format_sessions_table,
)
from faultline.schema import infer_json_schema
from faultline.storage import (
    ExchangeStore,
    export_har,
    export_jsonl,
    import_har,
    import_jsonl,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="faultline",
        description="Local HTTP traffic capture proxy, replay runner, and contract differ.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"faultline {__version__}",
    )
    parser.add_argument(
        "--db",
        default=".faultline/traffic.db",
        help="Path to SQLite traffic store (default: .faultline/traffic.db)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    p_record = subparsers.add_parser(
        "record",
        help="Start local recording reverse proxy",
    )
    p_record.add_argument(
        "--listen",
        default="127.0.0.1:9090",
        help="Host:port to bind local proxy (default: 127.0.0.1:9090)",
    )
    p_record.add_argument(
        "--upstream",
        required=True,
        help="Target upstream base URL (e.g. http://127.0.0.1:8000)",
    )
    p_record.add_argument(
        "--session",
        default="default",
        help="Capture session name (default: default)",
    )
    p_record.add_argument(
        "--no-redact",
        action="store_true",
        help="Disable header/body PII scrubbing",
    )

    p_sessions = subparsers.add_parser(
        "sessions",
        help="List recorded capture sessions and traffic stats",
    )
    p_sessions.add_argument(
        "--session",
        help="List exchanges for a specific session",
    )
    p_sessions.add_argument(
        "--dedupe",
        action="store_true",
        help="Filter to unique structural fingerprints only",
    )

    p_inspect = subparsers.add_parser(
        "inspect",
        help="Inspect request/response payload and inferred schema for an exchange",
    )
    p_inspect.add_argument("exchange_id", help="Exchange ID (or unique prefix)")

    p_replay = subparsers.add_parser(
        "replay",
        help="Replay a recorded session against a target URL and diff responses",
    )
    p_replay.add_argument("--session", required=True, help="Session name to replay")
    p_replay.add_argument("--target", required=True, help="Candidate target base URL")
    p_replay.add_argument(
        "--concurrency",
        type=int,
        default=4,
        help="Concurrent replay workers (default: 4)",
    )
    p_replay.add_argument(
        "--rate-limit",
        type=float,
        default=None,
        help="Max requests per second",
    )
    p_replay.add_argument(
        "--ignore-path",
        action="append",
        default=[],
        help="JSON path glob to ignore during diffing (repeatable)",
    )
    p_replay.add_argument(
        "--fail-on-added",
        action="store_true",
        help="Treat newly added JSON response fields as breaking errors",
    )
    p_replay.add_argument(
        "--max-latency-regression-ms",
        type=float,
        default=None,
        help="Flag exchanges whose latency regresses by more than N ms",
    )
    p_replay.add_argument(
        "--dedupe",
        action="store_true",
        help="Replay only one exchange per unique structural fingerprint",
    )
    p_replay.add_argument(
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format (default: text)",
    )

    p_diff = subparsers.add_parser(
        "diff",
        help="Compare two sessions or .jsonl/.har fixture files offline",
    )
    p_diff.add_argument("--baseline", required=True, help="Baseline session or fixture path")
    p_diff.add_argument("--candidate", required=True, help="Candidate session or fixture path")
    p_diff.add_argument(
        "--ignore-path",
        action="append",
        default=[],
        help="JSON path glob to ignore during diffing",
    )
    p_diff.add_argument(
        "--fail-on-added",
        action="store_true",
        help="Treat newly added JSON response fields as breaking errors",
    )
    p_diff.add_argument(
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format (default: text)",
    )

    p_schema = subparsers.add_parser(
        "schema",
        help="Infer merged JSON Schema across a session's responses",
    )
    p_schema.add_argument("--session", required=True, help="Session name")
    p_schema.add_argument(
        "--path-prefix",
        default=None,
        help="Optional route path prefix filter (e.g. /v1/charges)",
    )

    p_export = subparsers.add_parser(
        "export",
        help="Export a session to a .jsonl or .har file",
    )
    p_export.add_argument("--session", required=True, help="Session name to export")
    p_export.add_argument("--output", required=True, help="Destination file (.jsonl or .har)")

    p_import = subparsers.add_parser(
        "import",
        help="Import exchanges from a .jsonl or .har file into SQLite",
    )
    p_import.add_argument("--input", required=True, help="Source fixture file (.jsonl or .har)")
    p_import.add_argument("--session", default=None, help="Override session name on import")

    return parser


def _load_exchanges_from_ref(store: ExchangeStore, ref: str) -> list[HttpExchange]:
    if ref.endswith(".jsonl"):
        return import_jsonl(ref)
    if ref.endswith(".har"):
        return import_har(ref)
    return store.list_exchanges(session=ref)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    store = ExchangeStore(args.db)

    try:
        if args.command == "record":
            host, port_str = args.listen.rsplit(":", 1)
            port = int(port_str)
            policy = RedactionPolicy(enabled=not args.no_redact)
            redactor = Redactor(policy)

            def _log_exchange(ex: HttpExchange) -> None:
                print(
                    f"[captured] {ex.exchange_id} {ex.request.method:<6} {ex.request.path:<32} "
                    f"-> {ex.response.status_code} ({ex.response.latency_ms:.1f}ms) "
                    f"fp={ex.fingerprint}"
                )

            proxy = RecordingReverseProxy(
                listen_host=host,
                listen_port=port,
                upstream_url=args.upstream,
                session=args.session,
                store=store,
                redactor=redactor,
                on_capture=_log_exchange,
            )
            print(
                f"listening on http://{host}:{port} -> {args.upstream} (session={args.session})"
            )
            try:
                proxy.serve_forever()
            except KeyboardInterrupt:
                print("\nshutting down proxy")
            return 0

        if args.command == "sessions":
            if args.session:
                exchanges = store.list_exchanges(
                    session=args.session,
                    deduplicate_fingerprints=bool(args.dedupe),
                )
                print(format_exchanges_table(exchanges))
            else:
                summaries = store.list_sessions()
                print(format_sessions_table(summaries))
            return 0

        if args.command == "inspect":
            ex = store.get_exchange(args.exchange_id)
            if ex is None:
                print(f"error: exchange '{args.exchange_id}' not found", file=sys.stderr)
                return 1
            is_json, parsed_resp = ex.response.try_json_body()
            payload = {
                "exchange": ex.to_dict(),
                "route_template": ex.route_template,
                "inferred_response_schema": infer_json_schema([parsed_resp]) if is_json else None,
            }
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 0

        if args.command == "replay":
            exchanges = store.list_exchanges(
                session=args.session,
                deduplicate_fingerprints=bool(args.dedupe),
            )
            if not exchanges:
                print(
                    f"error: no recorded exchanges found for session '{args.session}'",
                    file=sys.stderr,
                )
                return 1
            ignored = set(DEFAULT_VOLATILE_PATHS) | set(args.ignore_path)
            diff_cfg = DiffConfig(
                ignore_paths=frozenset(ignored),
                fail_on_added_fields=bool(args.fail_on_added),
                max_latency_regression_ms=args.max_latency_regression_ms,
            )
            options = ReplayOptions(
                target_url=args.target,
                concurrency=args.concurrency,
                rate_limit_rps=args.rate_limit,
                diff_config=diff_cfg,
            )
            engine = ReplayEngine(options)
            report = engine.run(exchanges, session_name=args.session)
            print(format_replay_report(report, output_format=args.format))
            return 0 if report.passed else 2

        if args.command == "diff":
            base_exchanges = _load_exchanges_from_ref(store, args.baseline)
            cand_exchanges = _load_exchanges_from_ref(store, args.candidate)
            if not base_exchanges:
                print(f"error: baseline '{args.baseline}' is empty", file=sys.stderr)
                return 1
            if not cand_exchanges:
                print(f"error: candidate '{args.candidate}' is empty", file=sys.stderr)
                return 1

            ignored = set(DEFAULT_VOLATILE_PATHS) | set(args.ignore_path)
            differ = ContractDiffer(
                DiffConfig(
                    ignore_paths=frozenset(ignored),
                    fail_on_added_fields=bool(args.fail_on_added),
                )
            )

            cand_by_key: dict[tuple[str, str], HttpExchange] = {
                (ex.request.method, ex.request.path): ex for ex in cand_exchanges
            }
            comparisons: list[ExchangeComparison] = []
            for idx, base_ex in enumerate(base_exchanges):
                cand_ex = cand_by_key.get((base_ex.request.method, base_ex.request.path))
                if cand_ex is None and idx < len(cand_exchanges):
                    cand_ex = cand_exchanges[idx]
                if cand_ex is None:
                    comparisons.append(
                        differ.compare_exchange(
                            base_ex,
                            candidate=None,
                            transport_error="No matching candidate exchange found",
                        )
                    )
                else:
                    comparisons.append(differ.compare_exchange(base_ex, cand_ex.response))

            base_lat = LatencyStats.from_samples([c.baseline_latency_ms for c in comparisons])
            cand_lat = LatencyStats.from_samples(
                [c.candidate_latency_ms for c in comparisons if c.transport_error is None]
            )
            breaking_n = sum(1 for c in comparisons if c.has_breaking_changes)
            warn_n = sum(
                1 for c in comparisons if (not c.has_breaking_changes and c.has_warnings)
            )
            report = ReplayReport(
                session=str(args.baseline),
                target_url=f"offline://{args.candidate}",
                total_exchanges=len(comparisons),
                passed_count=len(comparisons) - breaking_n,
                breaking_count=breaking_n,
                warning_count=warn_n,
                baseline_latency=base_lat,
                candidate_latency=cand_lat,
                comparisons=comparisons,
            )
            print(format_replay_report(report, output_format=args.format))
            return 0 if report.passed else 2

        if args.command == "schema":
            exchanges = store.list_exchanges(
                session=args.session,
                path_prefix=args.path_prefix,
            )
            samples = []
            for ex in exchanges:
                ok, parsed = ex.response.try_json_body()
                if ok:
                    samples.append(parsed)
            if not samples:
                print(
                    f"error: no JSON response bodies in session '{args.session}'",
                    file=sys.stderr,
                )
                return 1
            schema = infer_json_schema(samples)
            print(json.dumps(schema, indent=2, sort_keys=True))
            return 0

        if args.command == "export":
            exchanges = store.list_exchanges(session=args.session)
            if args.output.endswith(".har"):
                count = export_har(exchanges, args.output)
            else:
                count = export_jsonl(exchanges, args.output)
            print(f"exported {count} exchanges from '{args.session}' to {args.output}")
            return 0

        if args.command == "import":
            if args.input.endswith(".har"):
                exchanges = import_har(args.input, session=args.session or "imported-har")
            else:
                exchanges = import_jsonl(args.input, override_session=args.session)
            saved = store.save_many(exchanges)
            print(f"imported {saved} exchanges from {args.input}")
            return 0

        return 1
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
