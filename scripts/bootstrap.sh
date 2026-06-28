#!/usr/bin/env bash
# Create a tenant and issue an API key via the control plane.
#
#   ./scripts/bootstrap.sh [tenant-id] [tenant-name]
#
# Prints the API key (shown once) and example commands.
set -euo pipefail

CP="${CONTROLPLANE_URL:-http://localhost:8081}"
GW="${GATEWAY_URL:-http://localhost:8080}"
QP="${QUERYPROXY_URL:-http://localhost:8082}"
TENANT="${1:-demo}"
NAME="${2:-Demo Tenant}"

curl -fsS -X POST "$CP/tenants" -H 'Content-Type: application/json' \
  -d "{\"id\":\"$TENANT\",\"name\":\"$NAME\"}" >/dev/null 2>&1 || true

KEY=$(curl -fsS -X POST "$CP/tenants/$TENANT/keys" | sed -n 's/.*"api_key":"\([^"]*\)".*/\1/p')
if [ -z "$KEY" ]; then
  echo "failed to issue API key (is the control plane up at $CP?)" >&2
  exit 1
fi

echo "Tenant:  $TENANT"
echo "API key: $KEY"
echo
echo "Try it:"
echo "  export MULTILOG_API_KEY=$KEY"
echo "  curl -s -X POST $GW/ingest -H \"X-API-Key: \$MULTILOG_API_KEY\" \\"
echo "    -d '[{\"source\":\"api\",\"message\":\"hello multi-log\"}]'"
echo "  curl -s \"$QP/logs\" -H \"X-API-Key: \$MULTILOG_API_KEY\""
echo
echo "For Vector:"
echo "  MULTILOG_API_KEY=$KEY docker compose -f deploy/docker-compose.yml --profile agents up -d vector"
