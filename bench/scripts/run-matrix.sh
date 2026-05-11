#!/usr/bin/env bash
# Drive the 2x2 (server impl × client impl) × 2 (transport) × 2 (direction)
# × N (jobs) bench matrix and feed all raw artifacts into aggregate.py.
#
# Env:
#   BENCH_SIZE          per-request bytes (default 1 GiB; passes through to run-pair.sh)
#   BENCH_REPS          repetitions per cell (default 3)
#   MATRIX_SERVERS      space-sep list of server impls (default: "sing rust")
#   MATRIX_CLIENTS      space-sep list of client impls (default: "sing rust")
#   MATRIX_TRANSPORTS   default: "h2 quic"
#   MATRIX_DIRECTIONS   default: "dl ul"
#   MATRIX_JOBS         default: "1 2 4"
#   COOLDOWN_SECS       sleep between cells (default 3)
#   STOP_ON_FAIL        1 to abort on first failed cell (default 0 = continue)
#   RESULTS_DIR         output dir (default bench/results)
#   MATRIX_PREFLIGHT_SMOKE
#                       1 to run a tiny sing-server/rust-client tunnel smoke
#                       before the full matrix when rust client is selected
#                       (default 1)

set -uo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
BENCH_DIR=$(cd -- "$SCRIPT_DIR/.." &>/dev/null && pwd)
BIN="$BENCH_DIR/.work/bin"
RESULTS_DIR=${RESULTS_DIR:-$BENCH_DIR/results}
RAW_DIR="$RESULTS_DIR/raw"
mkdir -p "$RAW_DIR"

MATRIX_SERVERS=${MATRIX_SERVERS:-"sing rust"}
MATRIX_CLIENTS=${MATRIX_CLIENTS:-"sing rust"}
MATRIX_TRANSPORTS=${MATRIX_TRANSPORTS:-"h2 quic"}
MATRIX_DIRECTIONS=${MATRIX_DIRECTIONS:-"dl ul"}
MATRIX_JOBS=${MATRIX_JOBS:-"1 2 4"}
COOLDOWN_SECS=${COOLDOWN_SECS:-3}
STOP_ON_FAIL=${STOP_ON_FAIL:-0}
MATRIX_PREFLIGHT_SMOKE=${MATRIX_PREFLIGHT_SMOKE:-1}

# Auto-skip rust rows if binaries are missing.
SERVERS=()
for s in $MATRIX_SERVERS; do
    if [[ "$s" == rust && ! -x "$BIN/trusttunnel_endpoint" ]]; then
        echo "[matrix] skipping server=rust (no $BIN/trusttunnel_endpoint)" >&2
        continue
    fi
    SERVERS+=("$s")
done
CLIENTS=()
for c in $MATRIX_CLIENTS; do
    if [[ "$c" == rust && ! -x "$BIN/trusttunnel_client" ]]; then
        echo "[matrix] skipping client=rust (no $BIN/trusttunnel_client)" >&2
        continue
    fi
    CLIENTS+=("$c")
done

if [[ ${#SERVERS[@]} -eq 0 || ${#CLIENTS[@]} -eq 0 ]]; then
    echo "[matrix] nothing to run (servers=${SERVERS[*]:-} clients=${CLIENTS[*]:-})" >&2
    exit 1
fi

has_rust_client=0
for c in "${CLIENTS[@]}"; do
    if [[ "$c" == rust ]]; then
        has_rust_client=1
        break
    fi
done

if [[ "$MATRIX_PREFLIGHT_SMOKE" == 1 && "$has_rust_client" == 1 ]]; then
    smoke_dir="$RAW_DIR/.smoke"
    smoke_label="sing-rust-h2-dl-j1"
    rm -rf "$smoke_dir"
    mkdir -p "$smoke_dir"
    echo "[matrix] preflight smoke: $smoke_label" >&2
    if ! BENCH_SIZE=1048576 BENCH_REPS=1 RESULTS_DIR="$smoke_dir" \
        "$SCRIPT_DIR/run-pair.sh" sing rust h2 dl 1 >"$smoke_dir/$smoke_label.driver.log" 2>&1; then
        echo "[matrix] preflight smoke FAILED → see $smoke_dir/$smoke_label.driver.log" >&2
        exit 1
    fi
    if ! grep -Eq 'request to [^_][^ ]*:8443' "$smoke_dir/$smoke_label.server.log"; then
        echo "[matrix] preflight smoke FAILED: rust client did not produce a tunneled origin request" >&2
        echo "[matrix] see $smoke_dir/$smoke_label.server.log" >&2
        exit 1
    fi
fi

started=$(date +%s)
total=0; ok=0; fail=0
echo "[matrix] start $(date '+%F %T') servers=(${SERVERS[*]}) clients=(${CLIENTS[*]}) transports=($MATRIX_TRANSPORTS) directions=($MATRIX_DIRECTIONS) jobs=($MATRIX_JOBS)" >&2

for s in "${SERVERS[@]}"; do
    for c in "${CLIENTS[@]}"; do
        for t in $MATRIX_TRANSPORTS; do
            for d in $MATRIX_DIRECTIONS; do
                for j in $MATRIX_JOBS; do
                    total=$(( total + 1 ))
                    label="$s-$c-$t-$d-j$j"
                    echo "[matrix] ($total) $label" >&2
                    if RESULTS_DIR="$RAW_DIR" "$SCRIPT_DIR/run-pair.sh" "$s" "$c" "$t" "$d" "$j" >"$RAW_DIR/$label.driver.log" 2>&1; then
                        ok=$(( ok + 1 ))
                    else
                        fail=$(( fail + 1 ))
                        echo "[matrix]   FAILED → see $RAW_DIR/$label.driver.log" >&2
                        if [[ "$STOP_ON_FAIL" == 1 ]]; then
                            echo "[matrix] STOP_ON_FAIL set, aborting" >&2
                            break 5
                        fi
                    fi
                    sleep "$COOLDOWN_SECS"
                done
            done
        done
    done
done

elapsed=$(( $(date +%s) - started ))
echo "[matrix] done in ${elapsed}s — total=$total ok=$ok fail=$fail" >&2

# Roll up
python3 "$SCRIPT_DIR/aggregate.py" "$RAW_DIR" "$RESULTS_DIR" || {
    echo "[matrix] aggregate.py failed" >&2
    exit 1
}

echo "[matrix] summary at $RESULTS_DIR/summary.csv and $RESULTS_DIR/summary.md" >&2
