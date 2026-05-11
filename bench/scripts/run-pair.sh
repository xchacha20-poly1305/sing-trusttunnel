#!/usr/bin/env bash
# Run a single bench cell: launches origin + tunnel-server + tunnel-client,
# fires a parallel curl array through the SOCKS5 listener, samples CPU/RSS,
# writes raw artifacts under results/raw/$LABEL.*. aggregate.py turns those
# into the summary CSV/MD.
#
# Usage: run-pair.sh <sing|rust> <sing|rust> <h2|quic> <dl|ul> <jobs>
#
# Env:
#   BENCH_SIZE       bytes per request (default 1073741824 = 1 GiB)
#   BENCH_REPS       repeat count (default 3)
#   BENCH_PIN        1 to pin via taskset when nproc >= 8 (default 1)
#   BENCH_TIMEOUT    per-curl timeout in seconds (default 180)
#   BENCH_ORIGIN_LISTEN origin listen address (default 0.0.0.0:8443)
#   BENCH_ORIGIN_HOST   origin host used by curl through SOCKS (default: primary local IP)
#   RESULTS_DIR      output dir (default bench/results/raw)

set -euo pipefail

usage() {
    sed -n '2,18p' "$0" >&2
}

[[ $# -eq 5 ]] || { usage; exit 1; }
SERVER=$1; CLIENT=$2; TRANSPORT=$3; DIRECTION=$4; JOBS=$5

case "$SERVER"     in sing|rust) ;; *) usage; exit 1;; esac
case "$CLIENT"     in sing|rust) ;; *) usage; exit 1;; esac
case "$TRANSPORT"  in h2|quic)   ;; *) usage; exit 1;; esac
case "$DIRECTION"  in dl|ul)     ;; *) usage; exit 1;; esac
[[ "$JOBS" =~ ^[0-9]+$ ]] || { usage; exit 1; }

BENCH_SIZE=${BENCH_SIZE:-1073741824}
BENCH_REPS=${BENCH_REPS:-3}
BENCH_TIMEOUT=${BENCH_TIMEOUT:-180}
BENCH_ORIGIN_LISTEN=${BENCH_ORIGIN_LISTEN:-0.0.0.0:8443}
BENCH_ORIGIN_HOST=${BENCH_ORIGIN_HOST:-$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -n1 || true)}
BENCH_ORIGIN_HOST=${BENCH_ORIGIN_HOST:-$(command -v hostname >/dev/null 2>&1 && hostname -I 2>/dev/null | awk '{print $1}' || true)}
BENCH_ORIGIN_HOST=${BENCH_ORIGIN_HOST:-127.0.0.1}
LABEL="$SERVER-$CLIENT-$TRANSPORT-$DIRECTION-j$JOBS"

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
BENCH_DIR=$(cd -- "$SCRIPT_DIR/.." &>/dev/null && pwd)
BIN="$BENCH_DIR/.work/bin"
CFG="$BENCH_DIR/configs"
WORK="$BENCH_DIR/.work"
RESULTS_DIR=${RESULTS_DIR:-$BENCH_DIR/results/raw}
mkdir -p "$RESULTS_DIR" "$WORK"
PREFIX="$RESULTS_DIR/$LABEL"

[[ -x "$BIN/sing-trusttunnel" ]] || { echo "missing $BIN/sing-trusttunnel; run setup.sh first" >&2; exit 1; }
[[ -x "$BIN/bench-origin"     ]] || { echo "missing $BIN/bench-origin"     >&2; exit 1; }
if [[ "$SERVER" == rust ]]; then
    [[ -x "$BIN/trusttunnel_endpoint" ]] || { echo "missing $BIN/trusttunnel_endpoint" >&2; exit 1; }
fi
if [[ "$CLIENT" == rust ]]; then
    [[ -x "$BIN/trusttunnel_client" ]] || { echo "missing $BIN/trusttunnel_client" >&2; exit 1; }
fi

PIN_SERVER=(); PIN_CLIENT=(); PIN_ORIGIN=(); PIN_CURL=()
if [[ "${BENCH_PIN:-1}" == "1" ]] && command -v taskset >/dev/null 2>&1 && [[ $(nproc) -ge 8 ]]; then
    PIN_SERVER=(taskset -c 2)
    PIN_CLIENT=(taskset -c 4)
    PIN_ORIGIN=(taskset -c 6)
    PIN_CURL=(taskset -c 8,10)   # curl array benefits from > 1 core
fi

PIDS=()
cleanup() {
    set +e
    local p
    for p in "${PIDS[@]:-}"; do
        kill -TERM "$p" 2>/dev/null
    done
    sleep 0.4
    for p in "${PIDS[@]:-}"; do
        kill -KILL "$p" 2>/dev/null
    done
}
trap cleanup EXIT INT TERM

wait_listen_tcp() {
    local host=$1 port=$2 deadline=$(( SECONDS + 15 ))
    while (( SECONDS < deadline )); do
        (exec 9<>"/dev/tcp/$host/$port") 2>/dev/null && { exec 9<&- 9>&-; return 0; }
        sleep 0.1
    done
    echo "timeout waiting for $host:$port (tcp)" >&2
    return 1
}

# Pre-flight: bail loudly if any of our ports is already taken so we don't
# silently bench a stale process from a previous run.
preflight_port_free() {
    local port=$1
    if (exec 9<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
        exec 9<&- 9>&-
        echo "[run-pair] port 127.0.0.1:$port already in use — aborting" >&2
        echo "[run-pair] hint: pkill -f 'bench-origin|sing-trusttunnel|trusttunnel_(endpoint|client)'" >&2
        return 1
    fi
    return 0
}
preflight_port_free "${BENCH_ORIGIN_LISTEN##*:}" || exit 1
preflight_port_free 4433 || exit 1
preflight_port_free 1080 || exit 1

# --- start origin ---
"${PIN_ORIGIN[@]}" "$BIN/bench-origin" \
    -listen "$BENCH_ORIGIN_LISTEN" \
    -cert "$BENCH_DIR/certs/cert.pem" \
    -key  "$BENCH_DIR/certs/key.pem" \
    > "$PREFIX.origin.log" 2>&1 &
ORIGIN_PID=$!
PIDS+=("$ORIGIN_PID")
wait_listen_tcp 127.0.0.1 8443

# --- start server ---
case "$SERVER" in
    sing)
        SERVER_CFG="$WORK/sing-server.$LABEL.json"
        cp "$CFG/sing-server.json" "$SERVER_CFG"
        (cd "$BENCH_DIR" && "${PIN_SERVER[@]}" "$BIN/sing-trusttunnel" \
            -c "$SERVER_CFG" server) > "$PREFIX.server.log" 2>&1 &
        SERVER_PID=$!
        ;;
    rust)
        (cd "$BENCH_DIR" && "${PIN_SERVER[@]}" "$BIN/trusttunnel_endpoint" \
            "$CFG/rust-server.vpn.toml" "$CFG/rust-server.hosts.toml") \
            > "$PREFIX.server.log" 2>&1 &
        SERVER_PID=$!
        ;;
esac
PIDS+=("$SERVER_PID")
wait_listen_tcp 127.0.0.1 4433
sleep 0.5  # let QUIC bind too

# --- start client ---
case "$CLIENT" in
    sing)
        CLIENT_CFG="$WORK/sing-client.$LABEL.json"
        QUIC_FLAG=false
        [[ "$TRANSPORT" == quic ]] && QUIC_FLAG=true
        jq --argjson q $QUIC_FLAG '.quic = $q' "$CFG/sing-client.json" > "$CLIENT_CFG"
        (cd "$BENCH_DIR" && "${PIN_CLIENT[@]}" "$BIN/sing-trusttunnel" \
            -c "$CLIENT_CFG" client) > "$PREFIX.client.log" 2>&1 &
        CLIENT_PID=$!
        ;;
    rust)
        CLIENT_CFG="$WORK/rust-client.$LABEL.toml"
        PROTO=http2
        [[ "$TRANSPORT" == quic ]] && PROTO=http3
        sed "s|^upstream_protocol = .*|upstream_protocol = \"$PROTO\"|" \
            "$CFG/rust-client.toml" > "$CLIENT_CFG"
        (cd "$BENCH_DIR" && "${PIN_CLIENT[@]}" "$BIN/trusttunnel_client" \
            --config "$CLIENT_CFG") > "$PREFIX.client.log" 2>&1 &
        CLIENT_PID=$!
        ;;
esac
PIDS+=("$CLIENT_PID")
wait_listen_tcp 127.0.0.1 1080
sleep 0.5

# --- start pidstat-collect (server + client + origin) ---
"$SCRIPT_DIR/pidstat-collect.sh" "$SERVER_PID" "$CLIENT_PID" "$ORIGIN_PID" \
    > "$PREFIX.pidstat.csv" 2>/dev/null &
PIDSTAT_PID=$!
PIDS+=("$PIDSTAT_PID")

# --- prepare upload payload (only for ul direction) ---
UPLOAD_TMP=""
if [[ "$DIRECTION" == ul ]]; then
    UPLOAD_TMP="$WORK/upload-$$.dat"
    dd if=/dev/zero of="$UPLOAD_TMP" bs=1M count=$(( (BENCH_SIZE + 1048575) / 1048576 )) status=none
fi

# --- run curl ---
> "$PREFIX.runs.txt"
URL_BASE="https://$BENCH_ORIGIN_HOST:8443"
CURL_COMMON=( -k -s
              --proxy "socks5://127.0.0.1:1080"
              --max-time "$BENCH_TIMEOUT"
              -w 'speed_dl=%{speed_download} speed_ul=%{speed_upload} time=%{time_total} code=%{http_code} size_dl=%{size_download} size_ul=%{size_upload}\n'
              -o /dev/null )

run_curl_job() {
    local rep=$1 job=$2 tmpfile
    tmpfile=$(mktemp)
    if [[ "$DIRECTION" == dl ]]; then
        "${PIN_CURL[@]}" curl "${CURL_COMMON[@]}" \
            "$URL_BASE/download/$BENCH_SIZE" >"$tmpfile" 2>&1
    else
        "${PIN_CURL[@]}" curl "${CURL_COMMON[@]}" -X PUT \
            --data-binary "@$UPLOAD_TMP" \
            "$URL_BASE/upload/test-$rep-$job" >"$tmpfile" 2>&1
    fi
    local rc=$?
    awk -v rep="$rep" -v job="$job" -v rc="$rc" \
        '{print "rep="rep, "job="job, "rc="rc, $0}' "$tmpfile"
    rm -f "$tmpfile"
    return 0
}

for rep in $(seq 1 "$BENCH_REPS"); do
    JOB_PIDS=()
    for j in $(seq 1 "$JOBS"); do
        ( run_curl_job "$rep" "$j" >> "$PREFIX.runs.txt" ) &
        JOB_PIDS+=($!)
    done
    for p in "${JOB_PIDS[@]}"; do
        wait "$p" || true
    done
done

[[ -n "$UPLOAD_TMP" && -f "$UPLOAD_TMP" ]] && rm -f "$UPLOAD_TMP"

# stop pidstat (do this BEFORE killing tunnel pids so it can read /proc cleanly)
kill -TERM "$PIDSTAT_PID" 2>/dev/null || true
wait "$PIDSTAT_PID" 2>/dev/null || true

# --- write meta.json ---
cat > "$PREFIX.meta.json" <<EOF
{
  "label": "$LABEL",
  "server": "$SERVER",
  "client": "$CLIENT",
  "transport": "$TRANSPORT",
  "direction": "$DIRECTION",
  "jobs": $JOBS,
  "reps": $BENCH_REPS,
  "size_bytes": $BENCH_SIZE,
  "origin_listen": "$BENCH_ORIGIN_LISTEN",
  "origin_host": "$BENCH_ORIGIN_HOST",
  "server_pid": $SERVER_PID,
  "client_pid": $CLIENT_PID,
  "origin_pid": $ORIGIN_PID
}
EOF

if ! awk '
    BEGIN { total = 0; bad = 0 }
    {
        total++
        rc = ""
        code = ""
        for (i = 1; i <= NF; i++) {
            split($i, kv, "=")
            if (kv[1] == "rc") rc = kv[2]
            if (kv[1] == "code") code = kv[2]
        }
        if (rc != "0" || code != "200") {
            bad = 1
            print "[run-pair] failed curl: " $0 > "/dev/stderr"
        }
    }
    END {
        if (total == 0) {
            print "[run-pair] no curl results" > "/dev/stderr"
            bad = 1
        }
        exit bad
    }
' "$PREFIX.runs.txt"; then
    exit 1
fi

expected_runs=$(( BENCH_REPS * JOBS ))
actual_runs=$(wc -l < "$PREFIX.runs.txt")
if [[ "$actual_runs" -ne "$expected_runs" ]]; then
    echo "[run-pair] expected $expected_runs curl results, got $actual_runs" >&2
    exit 1
fi

echo "[run-pair] $LABEL → $PREFIX.{runs.txt,pidstat.csv,meta.json}" >&2
