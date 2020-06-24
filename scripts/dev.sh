#!/usr/bin/env bash
set -e

export GRPC_GO_LOG_VERBOSITY_LEVEL=2
export GRPC_GO_LOG_SEVERITY_LEVEL=info

pkill vault || true

make dev
mkdir -p bin/
cp "$GOPATH/bin/vault-plugin-secrets-gcp-cab" bin/

vault server \
  -log-level=warn \
  -dev \
  -dev-plugin-dir="$(pwd)/bin" &
VAULT_PID=$!
sleep 2

vault secrets enable -path=gcpcab -plugin-name=vault-plugin-secrets-gcp-cab plugin
