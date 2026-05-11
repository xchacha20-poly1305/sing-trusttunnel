#!/usr/bin/env bash
# Sample CPU% and RSS for a list of PIDs at 1 Hz, emit CSV to stdout.
# Stops cleanly on SIGTERM/SIGINT.
#
# Usage: pidstat-collect.sh PID [PID...]
#
# CSV columns: ts_unix,pid,cpu_pct,rss_kb,vsz_kb,comm

set -euo pipefail

PIDS=("$@")
[[ ${#PIDS[@]} -gt 0 ]] || { echo "usage: $0 PID [PID...]" >&2; exit 1; }

CLK_TCK=$(getconf CLK_TCK)

# Read utime+stime sum (in jiffies) from /proc/$pid/stat. Stat field layout:
#   pid (comm) state ppid pgrp ... utime stime cutime cstime ...
# utime is field 14, stime is field 15. The (comm) can contain spaces and
# parens, so we slice from the last ')' to be safe.
read_jiffies() {
    local pid=$1 line tail
    if ! line=$(cat "/proc/$pid/stat" 2>/dev/null); then
        echo ""
        return
    fi
    tail=${line##*\)}            # everything after the last ')'
    # tail starts with a space then state at field 3
    set -- $tail
    # $1=state $2=ppid ... $12=utime $13=stime  (because we dropped 1 and 2 above)
    echo "$(( ${12} + ${13} ))"
}

read_rss_vsz() {
    local pid=$1 rss="" vsz=""
    if [[ ! -r "/proc/$pid/status" ]]; then
        echo ", "
        return
    fi
    while IFS= read -r line; do
        case $line in
            VmRSS:*) rss=${line#VmRSS:}; rss=${rss// /}; rss=${rss%kB} ;;
            VmSize:*) vsz=${line#VmSize:}; vsz=${vsz// /}; vsz=${vsz%kB} ;;
        esac
    done < "/proc/$pid/status"
    echo "$rss,$vsz"
}

read_comm() {
    local pid=$1
    if [[ -r "/proc/$pid/comm" ]]; then
        tr -d '\n' < "/proc/$pid/comm"
    else
        echo ""
    fi
}

declare -A LAST_J
declare -A LAST_T

# Init jiffy baseline.
for pid in "${PIDS[@]}"; do
    j=$(read_jiffies "$pid" || true)
    LAST_J[$pid]=${j:-0}
    LAST_T[$pid]=$(date +%s.%N)
done

stop=0
trap 'stop=1' INT TERM HUP
ORIG_PARENT=$PPID

echo "ts_unix,pid,cpu_pct,rss_kb,vsz_kb,comm"

while [[ $stop -eq 0 ]]; do
    sleep 1
    # Bail out if our parent shell died — keeps us from becoming an orphan
    # spinning forever after the orchestrator script is killed.
    if ! kill -0 "$ORIG_PARENT" 2>/dev/null; then
        break
    fi
    now=$(date +%s.%N)
    ts=${now%.*}
    for pid in "${PIDS[@]}"; do
        if [[ ! -d "/proc/$pid" ]]; then
            continue
        fi
        j_now=$(read_jiffies "$pid" || true)
        if [[ -z "$j_now" ]]; then
            continue
        fi
        prev_j=${LAST_J[$pid]:-$j_now}
        prev_t=${LAST_T[$pid]:-$now}
        dt=$(awk -v a="$now" -v b="$prev_t" 'BEGIN{printf "%.6f", a-b}')
        dj=$(( j_now - prev_j ))
        if awk -v dt="$dt" 'BEGIN{exit !(dt>0)}'; then
            cpu_pct=$(awk -v dj="$dj" -v dt="$dt" -v hz="$CLK_TCK" \
                'BEGIN{printf "%.2f", (dj/hz)/dt*100}')
        else
            cpu_pct=0
        fi
        LAST_J[$pid]=$j_now
        LAST_T[$pid]=$now
        rss_vsz=$(read_rss_vsz "$pid")
        comm=$(read_comm "$pid")
        echo "$ts,$pid,$cpu_pct,$rss_vsz,$comm"
    done
done
