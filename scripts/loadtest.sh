#!/usr/bin/env bash
# Reproduces the numbers in docs/SCALE.md: starts a throwaway Postgres 16 in
# Docker, seeds users and sessions, and sweeps session lookup and sign-in.
# Needs Docker and Go. Results depend on your hardware; docs/SCALE.md lists
# the machine its numbers came from. Run it on an otherwise idle machine:
# the load generator, server and database share it.
#
#   scripts/loadtest.sh [users] [repetitions]     (defaults 100000 and 3)

set -euo pipefail
users="${1:-100000}"
reps="${2:-3}"
cd "$(dirname "$0")/.."
dsn="postgres://postgres:pw@localhost:55432/ta"
bin="$(mktemp -d)/theauth-loadtest"
srv_pid=""

cleanup() {
	[ -n "$srv_pid" ] && kill "$srv_pid" 2>/dev/null || true
	docker rm -f theauth-loadtest-pg >/dev/null 2>&1 || true
}
trap cleanup EXIT

go build -o "$bin" ./cmd/theauth-loadtest
docker rm -f theauth-loadtest-pg >/dev/null 2>&1 || true
docker run -d --name theauth-loadtest-pg -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=ta -p 55432:5432 postgres:16 >/dev/null
until docker exec theauth-loadtest-pg pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
sleep 2
docker exec theauth-loadtest-pg psql -U postgres -d ta -c "CREATE EXTENSION IF NOT EXISTS citext" >/dev/null

"$bin" seed -db "$dsn" -users "$users"

port_open() { (exec 3<>/dev/tcp/127.0.0.1/8090) 2>/dev/null; }

serve() {
	if [ -n "$srv_pid" ]; then
		kill "$srv_pid" 2>/dev/null || true
		wait "$srv_pid" 2>/dev/null || true
		while port_open; do sleep 0.5; done
	fi
	"$bin" serve -db "$dsn" "$@" >/dev/null 2>&1 &
	srv_pid=$!
	until port_open; do
		kill -0 "$srv_pid" 2>/dev/null || { echo "server failed to start" >&2; exit 1; }
		sleep 0.5
	done
}

rss() { ps -o rss= -p "$srv_pid" | awk '{printf "%d MB", $1/1024}'; }

echo "== session lookup over HTTP by connection pool size (64 clients)"
for pool in 4 14 32; do
	serve -max-conns "$pool"
	for i in $(seq 1 "$reps"); do
		echo "pool=$pool $("$bin" run -scenario session -c 64 -d 12s -users "$users")"
	done
done

echo "== sign-in by Argon2id concurrency bound (64 clients)"
for conc in 1 2 3 4 7; do
	serve -hash-conc "$conc"
	for i in $(seq 1 "$reps"); do
		echo "hash-conc=$conc $("$bin" run -scenario signin -c 64 -d 12s -users "$users") rss=$(rss)"
	done
done

kill "$srv_pid" 2>/dev/null || true

echo "== storage path: two queries vs one joined query, parallel, no HTTP"
for i in $(seq 1 "$reps"); do
	for mode in two-query joined; do
		docker exec theauth-loadtest-pg psql -U postgres -c "DROP DATABASE IF EXISTS b" >/dev/null 2>&1
		docker exec theauth-loadtest-pg psql -U postgres -c "CREATE DATABASE b" >/dev/null 2>&1
		docker exec theauth-loadtest-pg psql -U postgres -d b -c "CREATE EXTENSION citext" >/dev/null
		POSTGRES_TEST_URL="postgres://postgres:pw@localhost:55432/b" \
			go test ./storage/postgres -run '^$' -bench "SessionLookup/${mode}\$" -benchtime=4s 2>&1 |
			awk -v m="$mode" '/^Benchmark/ {printf "%-9s %s ns/op\n", m, $3}'
	done
done
