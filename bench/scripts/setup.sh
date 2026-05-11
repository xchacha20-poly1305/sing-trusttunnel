#!/usr/bin/env bash
# Prepare bench dependencies: build sing-trusttunnel, build TrustTunnel rust
# endpoint, optionally clone+build TrustTunnelClient, build the origin server,
# generate certs.
#
# Layout (relative to repo root):
#   bench/.work/bin/sing-trusttunnel              <- Go binary (sing CLI)
#   bench/.work/bin/bench-origin                  <- Go HTTPS origin
#   bench/.work/bin/trusttunnel_endpoint          <- rust server
#   bench/.work/bin/trusttunnel_client            <- rust client (optional)
#   bench/.work/TrustTunnelClient/                <- cloned client repo
#
# Env knobs:
#   TRUSTTUNNEL_DIR       path to TrustTunnel rust repo (default: ../TrustTunnel)
#   TRUSTTUNNELCLIENT_URL git URL of TrustTunnelClient (default: upstream)
#   SKIP_CLIENT=1         do not clone/build the rust client (half matrix only)
#   SKIP_RUST_SERVER=1    do not build the rust endpoint
#   FORCE_CERT=1          regenerate cert even if it exists

set -euo pipefail

BENCH_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &>/dev/null && pwd)
REPO_ROOT=$(cd -- "$BENCH_DIR/.." &>/dev/null && pwd)
WORK="$BENCH_DIR/.work"
BIN="$WORK/bin"
mkdir -p "$BIN"

TRUSTTUNNEL_DIR=${TRUSTTUNNEL_DIR:-$REPO_ROOT/../TrustTunnel}
TRUSTTUNNELCLIENT_URL=${TRUSTTUNNELCLIENT_URL:-https://github.com/TrustTunnel/TrustTunnelClient.git}

log() { printf '\033[1;34m[setup]\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33m[setup]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[setup]\033[0m %s\n' "$*" >&2; exit 1; }

require() {
    command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"
}

log "checking tools"
require go
require curl
require openssl
require jq
command -v taskset >/dev/null 2>&1 || warn "taskset not found; CPU pinning will be skipped"

log "generating cert (if missing)"
FORCE=${FORCE_CERT:-0} "$BENCH_DIR/certs/gen-cert.sh"

log "building sing-trusttunnel + bench-origin"
(
    cd "$REPO_ROOT"
    go build -trimpath -ldflags='-w -s' -tags with_quic \
        -o "$BIN/sing-trusttunnel" ./cmd/sing-trusttunnel
    go build -trimpath -ldflags='-w -s' \
        -o "$BIN/bench-origin" ./bench/origin
)

if [[ "${SKIP_RUST_SERVER:-0}" != "1" ]]; then
    if [[ ! -d "$TRUSTTUNNEL_DIR" ]]; then
        die "TrustTunnel rust repo not found at $TRUSTTUNNEL_DIR (override with TRUSTTUNNEL_DIR=...)"
    fi
    require cargo
    log "building TrustTunnel rust endpoint at $TRUSTTUNNEL_DIR"
    (
        cd "$TRUSTTUNNEL_DIR"
        cargo build --release -p trusttunnel_endpoint
    )
    cp -f "$TRUSTTUNNEL_DIR/target/release/trusttunnel_endpoint" "$BIN/"
else
    warn "SKIP_RUST_SERVER=1 set, skipping rust endpoint build"
fi

if [[ "${SKIP_CLIENT:-0}" != "1" ]]; then
    CLIENT_DIR="$WORK/TrustTunnelClient"
    if [[ ! -d "$CLIENT_DIR" ]]; then
        log "cloning TrustTunnelClient"
        if ! git clone --depth=1 "$TRUSTTUNNELCLIENT_URL" "$CLIENT_DIR"; then
            warn "failed to clone TrustTunnelClient; rust-client rows will be skipped in the matrix"
            warn "set SKIP_CLIENT=1 to silence, or run setup again with network available"
            exit 0
        fi
    fi
    require cargo
    log "building TrustTunnelClient (this can take a while)"
    if (
        cd "$CLIENT_DIR"
        if [[ -f Cargo.toml ]]; then
            cargo build --release --bin trusttunnel_client
            mkdir -p "$BIN"
            cp -f "$(find target/release -maxdepth 2 -name trusttunnel_client -type f | head -n1)" "$BIN/" 2>/dev/null
        elif [[ -f Makefile ]] && command -v conan >/dev/null 2>&1; then
            EXPORT_DIR="$BIN/trusttunnel-client-build" make build_and_export_bin
            cp -f "$BIN/trusttunnel-client-build/trusttunnel_client" "$BIN/"
        elif [[ -x scripts/install.sh ]]; then
            "$CLIENT_DIR/scripts/install.sh" -o "$WORK/trusttunnel-client-release" -a y
            cp -f "$WORK/trusttunnel-client-release/trusttunnel_client" "$BIN/"
        else
            echo "no supported TrustTunnelClient build/install path found" >&2
            exit 1
        fi
    ); then
        log "rust client built"
    else
        warn "TrustTunnelClient build failed; rust-client rows will be skipped"
        warn "build it manually and copy the binary to $BIN/trusttunnel_client"
    fi
else
    warn "SKIP_CLIENT=1 set, skipping rust client build"
fi

log "binaries:"
ls -lh "$BIN" >&2 || true
log "setup done"
