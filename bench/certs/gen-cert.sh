#!/usr/bin/env bash
# Generate a self-signed cert/key suitable for the bench:
# CN/SAN = bench.local + 127.0.0.1 + ::1
set -euo pipefail

SELF_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
CERT="$SELF_DIR/cert.pem"
KEY="$SELF_DIR/key.pem"

if [[ -f "$CERT" && -f "$KEY" && "${FORCE:-0}" != "1" ]]; then
    echo "cert already exists at $CERT (set FORCE=1 to regenerate)" >&2
    exit 0
fi

CONF=$(mktemp)
trap 'rm -f "$CONF"' EXIT
cat > "$CONF" <<'EOF'
[req]
distinguished_name = dn
prompt             = no
x509_extensions    = v3_ext

[dn]
CN = bench.local

[v3_ext]
subjectAltName = @alt
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[alt]
DNS.1 = bench.local
DNS.2 = localhost
IP.1  = 127.0.0.1
IP.2  = ::1
EOF

openssl req -x509 -newkey ec:<(openssl ecparam -name prime256v1) \
    -keyout "$KEY" -out "$CERT" \
    -days 365 -nodes -config "$CONF"

chmod 600 "$KEY"
echo "wrote $CERT and $KEY"
