#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "== gofmt =="
UNFORMATTED=$(gofmt -l .)
if [ -n "$UNFORMATTED" ]; then echo "MAL formateado:"; echo "$UNFORMATTED"; exit 1; fi
echo "OK"

echo "== go vet =="
go vet ./...
echo "OK"

echo "== go test (con race) =="
go test -race ./...

echo "== build linux/amd64 =="
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/pxproxy-linux-amd64 .
echo "OK -> dist/pxproxy-linux-amd64"

echo "VERIFICACION COMPLETA"
