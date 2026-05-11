#!/usr/bin/env python3
"""Aggregate raw bench artifacts into summary.csv and summary.md.

Reads each *.meta.json in the raw dir, joins it with its matching *.runs.txt
and *.pidstat.csv, and emits per-cell statistics:

  - throughput per curl invocation (parsed from curl -w speed_dl/speed_ul)
  - mean / stddev / min / max throughput across all (rep × job) samples
  - aggregate throughput (sum of per-job means inside each rep, mean across reps)
  - server / client / origin %CPU and RSS (mean and p95 over the bench window)
"""
from __future__ import annotations

import csv
import json
import math
import re
import statistics
import sys
from collections import defaultdict
from pathlib import Path
from typing import Iterable

_KV_RE = re.compile(r"(\w+)=(\S+)")


def parse_runs(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        kv = dict(_KV_RE.findall(line))
        if not kv:
            continue
        try:
            rows.append({
                "rep": int(kv.get("rep", 0)),
                "job": int(kv.get("job", 0)),
                "rc": int(kv.get("rc", -1)),
                "speed_dl": float(kv.get("speed_dl", 0) or 0),
                "speed_ul": float(kv.get("speed_ul", 0) or 0),
                "time": float(kv.get("time", 0) or 0),
                "code": int(kv.get("code", 0) or 0),
                "size_dl": int(kv.get("size_dl", 0) or 0),
                "size_ul": int(kv.get("size_ul", 0) or 0),
            })
        except ValueError:
            continue
    return rows


def parse_pidstat(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    with path.open(newline="") as f:
        reader = csv.DictReader(f)
        for r in reader:
            try:
                rows.append({
                    "ts": int(r["ts_unix"]),
                    "pid": int(r["pid"]),
                    "cpu": float(r["cpu_pct"]),
                    "rss": int((r["rss_kb"] or "0").strip() or 0),
                    "vsz": int((r["vsz_kb"] or "0").strip() or 0),
                    "comm": (r.get("comm") or "").strip(),
                })
            except (ValueError, KeyError):
                continue
    return rows


def stats(values: Iterable[float]) -> dict:
    vs = [v for v in values if v is not None]
    if not vs:
        return {"n": 0, "mean": 0.0, "stddev": 0.0, "min": 0.0, "max": 0.0, "p95": 0.0}
    vs_sorted = sorted(vs)
    p95 = vs_sorted[min(len(vs_sorted) - 1, int(math.ceil(0.95 * len(vs_sorted)) - 1))]
    return {
        "n": len(vs),
        "mean": statistics.fmean(vs),
        "stddev": statistics.pstdev(vs) if len(vs) > 1 else 0.0,
        "min": min(vs),
        "max": max(vs),
        "p95": p95,
    }


def per_proc_stats(samples: list[dict], pid: int) -> dict:
    sub = [s for s in samples if s["pid"] == pid]
    cpu = stats([s["cpu"] for s in sub])
    rss = stats([s["rss"] for s in sub])
    return {
        "samples": cpu["n"],
        "cpu_mean": cpu["mean"],
        "cpu_p95": cpu["p95"],
        "cpu_max": cpu["max"],
        "rss_mean_kb": rss["mean"],
        "rss_max_kb": rss["max"],
    }


def aggregate_cell(prefix: Path, meta: dict) -> dict:
    runs = parse_runs(prefix.with_suffix(".runs.txt"))
    pidstat = parse_pidstat(prefix.with_suffix(".pidstat.csv"))

    direction = meta["direction"]
    speed_field = "speed_dl" if direction == "dl" else "speed_ul"

    ok_runs = [r for r in runs if r["rc"] == 0 and r["code"] == 200]
    speeds = [r[speed_field] for r in ok_runs]
    sp = stats(speeds)

    # Aggregate throughput per rep: sum of per-job speeds within a rep.
    by_rep: dict[int, list[float]] = defaultdict(list)
    for r in ok_runs:
        by_rep[r["rep"]].append(r[speed_field])
    agg_per_rep = [sum(v) for v in by_rep.values()]
    agg = stats(agg_per_rep)

    server = per_proc_stats(pidstat, meta["server_pid"])
    client = per_proc_stats(pidstat, meta["client_pid"])
    origin = per_proc_stats(pidstat, meta.get("origin_pid", 0))

    return {
        "label": meta["label"],
        "server_impl": meta["server"],
        "client_impl": meta["client"],
        "transport": meta["transport"],
        "direction": direction,
        "jobs": meta["jobs"],
        "reps": meta["reps"],
        "size_bytes": meta["size_bytes"],
        "runs_ok": len(ok_runs),
        "runs_fail": len(runs) - len(ok_runs),
        "per_job_speed_Bps_mean": sp["mean"],
        "per_job_speed_Bps_stddev": sp["stddev"],
        "per_job_speed_Bps_min": sp["min"],
        "per_job_speed_Bps_max": sp["max"],
        "agg_speed_Bps_mean": agg["mean"],
        "agg_speed_Bps_stddev": agg["stddev"],
        "server_cpu_mean": server["cpu_mean"],
        "server_cpu_p95": server["cpu_p95"],
        "server_rss_max_kb": server["rss_max_kb"],
        "client_cpu_mean": client["cpu_mean"],
        "client_cpu_p95": client["cpu_p95"],
        "client_rss_max_kb": client["rss_max_kb"],
        "origin_cpu_mean": origin["cpu_mean"],
        "origin_cpu_p95": origin["cpu_p95"],
    }


def fmt_MBps(bps: float) -> str:
    return f"{bps / (1024 * 1024):.1f}"


def fmt_MiB(kb: float) -> str:
    return f"{kb / 1024:.1f}"


def write_csv(rows: list[dict], path: Path) -> None:
    if not rows:
        path.write_text("# no rows\n")
        return
    cols = list(rows[0].keys())
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def write_md(rows: list[dict], path: Path) -> None:
    if not rows:
        path.write_text("# no rows\n")
        return

    rows = sorted(rows, key=lambda r: (r["transport"], r["direction"], r["jobs"],
                                       r["server_impl"], r["client_impl"]))
    grouped: dict[tuple, list[dict]] = defaultdict(list)
    for r in rows:
        grouped[(r["transport"], r["direction"], r["jobs"])].append(r)

    lines: list[str] = []
    lines.append("# Bench summary\n")
    lines.append("Throughput in MB/s (1 MB = 1 048 576 B). RSS in MiB. CPU as %CPU (single-core baseline = 100%).\n")
    lines.append("`per_job` = mean per concurrent curl invocation; `agg` = sum across jobs in a rep, then mean across reps.\n")

    for (transport, direction, jobs), block in grouped.items():
        lines.append(f"\n## transport={transport}  direction={direction}  jobs={jobs}\n")
        lines.append("| server | client | per_job MB/s (±σ) | agg MB/s (±σ) | server %cpu p95 | server RSS MiB | client %cpu p95 | client RSS MiB | runs ok/fail |")
        lines.append("| - | - | - | - | - | - | - | - | - |")
        for r in block:
            lines.append("| {srv} | {cli} | {pj} ± {pjs} | {ag} ± {ags} | {scpu:.1f} | {srss} | {ccpu:.1f} | {crss} | {ok}/{fail} |".format(
                srv=r["server_impl"], cli=r["client_impl"],
                pj=fmt_MBps(r["per_job_speed_Bps_mean"]),
                pjs=fmt_MBps(r["per_job_speed_Bps_stddev"]),
                ag=fmt_MBps(r["agg_speed_Bps_mean"]),
                ags=fmt_MBps(r["agg_speed_Bps_stddev"]),
                scpu=r["server_cpu_p95"], srss=fmt_MiB(r["server_rss_max_kb"]),
                ccpu=r["client_cpu_p95"], crss=fmt_MiB(r["client_rss_max_kb"]),
                ok=r["runs_ok"], fail=r["runs_fail"],
            ))

    path.write_text("\n".join(lines) + "\n")


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <raw_dir> <out_dir>", file=sys.stderr)
        return 2
    raw_dir = Path(sys.argv[1])
    out_dir = Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)

    rows: list[dict] = []
    for meta_path in sorted(raw_dir.glob("*.meta.json")):
        try:
            meta = json.loads(meta_path.read_text())
        except Exception as e:
            print(f"skip {meta_path.name}: {e}", file=sys.stderr)
            continue
        prefix = meta_path.with_suffix("")  # strip .json
        # meta_path is "X.meta.json"; with_suffix("") gives "X.meta", we want "X"
        prefix = Path(str(meta_path)[:-len(".meta.json")])
        rows.append(aggregate_cell(prefix, meta))

    write_csv(rows, out_dir / "summary.csv")
    write_md(rows, out_dir / "summary.md")
    print(f"wrote {len(rows)} rows → {out_dir}/summary.csv and summary.md", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
