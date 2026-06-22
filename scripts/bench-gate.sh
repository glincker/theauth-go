#!/usr/bin/env bash
# scripts/bench-gate.sh
#
# Run the curated benchmark suite and print benchstat-compatible output.
# Exits 0 on success. Exits non-zero if benchstat finds any regression
# exceeding THRESHOLD_PCT (default 25) when called in comparison mode.
#
# Usage (standalone -- produces benchmark output):
#   ./scripts/bench-gate.sh
#
# Usage (comparison -- called by the CI workflow):
#   # Step 1: produce base output
#   ./scripts/bench-gate.sh > base-bench.txt
#   # Step 2 (on PR branch): produce PR output
#   ./scripts/bench-gate.sh > pr-bench.txt
#   # Step 3: diff and check
#   benchstat base-bench.txt pr-bench.txt | tee diff.txt
#   ./scripts/bench-gate.sh --check diff.txt
#
# Environment variables:
#   THRESHOLD_PCT   Percentage regression allowed (default: 25).
#   BENCH_PIN       Set to "1" to pin to a single CPU core via taskset
#                   (reduces scheduling noise on Linux runners that support
#                   taskset; silently skipped if taskset is unavailable).
#   BENCH_TIME      benchtime flag value (default: 2s).
#   BENCH_COUNT     -count flag value (default: 10).
#
# Benchmark names are read from benchgate/curated.txt. Lines beginning with
# '#' and blank lines are ignored. A line of the form:
#   # gate:skip BenchmarkFoo -- reason
# causes BenchmarkFoo to be excluded from the -run regex and from threshold
# checks (it will NOT appear in the output).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CURATED="${REPO_ROOT}/benchgate/curated.txt"
THRESHOLD_PCT="${THRESHOLD_PCT:-25}"
BENCH_TIME="${BENCH_TIME:-2s}"
BENCH_COUNT="${BENCH_COUNT:-10}"

# --check mode: parse benchstat diff output and exit non-zero on regressions.
if [[ "${1:-}" == "--check" ]]; then
    diff_file="${2:?Usage: bench-gate.sh --check <diff.txt>}"
    if [[ ! -f "${diff_file}" ]]; then
        echo "ERROR: diff file not found: ${diff_file}" >&2
        exit 1
    fi
    failed=0
    # benchstat delta column looks like "+12.3%" or "-5.1%" or "~" (no change).
    # We look for lines where the delta column is a positive number exceeding
    # THRESHOLD_PCT. The delta column is the last numeric % field on a line.
    while IFS= read -r line; do
        # Skip header lines and lines without a % sign.
        if [[ "${line}" != *%* ]]; then
            continue
        fi
        # Extract the last occurrence of +N.N% or -N.N%.
        delta=$(echo "${line}" | grep -oE '[+-][0-9]+(\.[0-9]+)?%' | tail -1 || true)
        if [[ -z "${delta}" ]]; then
            continue
        fi
        # Strip % and sign for numeric comparison.
        abs_val=$(echo "${delta}" | tr -d '+-' | tr -d '%')
        direction=$(echo "${delta}" | cut -c1)
        # Only regressions (positive delta = slower) trigger failure.
        if [[ "${direction}" == "+" ]]; then
            # Use awk for floating-point comparison.
            exceeds=$(awk -v val="${abs_val}" -v thr="${THRESHOLD_PCT}" 'BEGIN{print (val > thr) ? "yes" : "no"}')
            if [[ "${exceeds}" == "yes" ]]; then
                echo "REGRESSION: ${line}" >&2
                failed=1
            fi
        fi
    done < "${diff_file}"
    if [[ "${failed}" -eq 1 ]]; then
        echo "" >&2
        echo "bench-gate: one or more benchmarks regressed more than ${THRESHOLD_PCT}%." >&2
        echo "Review the diff above and fix before merging." >&2
        exit 1
    fi
    echo "bench-gate: all benchmarks within threshold (${THRESHOLD_PCT}%)." >&2
    exit 0
fi

# Build the -run regex from curated.txt, excluding gate:skip entries.
skipped=()
included=()
while IFS= read -r line; do
    # Strip leading/trailing whitespace.
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    # Blank lines.
    [[ -z "${line}" ]] && continue
    # gate:skip comment.
    if [[ "${line}" == "# gate:skip"* ]]; then
        name=$(echo "${line}" | awk '{print $3}')
        [[ -n "${name}" ]] && skipped+=("${name}")
        continue
    fi
    # Regular comment.
    [[ "${line}" == "#"* ]] && continue
    included+=("${line}")
done < "${CURATED}"

if [[ ${#included[@]} -eq 0 ]]; then
    echo "ERROR: benchgate/curated.txt is empty or all entries are skipped." >&2
    exit 1
fi

# Join with | for -bench regex.
bench_regex=$(printf "%s|" "${included[@]}")
bench_regex="${bench_regex%|}"  # trim trailing |

# Determine packages that contain the curated benchmarks.
# We always run these two packages; expand if new packages are added.
packages=(
    "./crypto/..."
    "./internal/bench/..."
    "./internal/jwt/..."
    "."
)

echo "bench-gate: running ${#included[@]} curated benchmarks (skipping ${#skipped[@]})" >&2
echo "bench-gate: threshold = ${THRESHOLD_PCT}%  benchtime = ${BENCH_TIME}  count = ${BENCH_COUNT}" >&2
if [[ ${#skipped[@]} -gt 0 ]]; then
    echo "bench-gate: skipped: ${skipped[*]}" >&2
fi

# Optional single-core pinning to reduce scheduler noise on Linux runners.
pin_prefix=()
if [[ "${BENCH_PIN:-}" == "1" ]]; then
    if command -v taskset &>/dev/null; then
        pin_prefix=(taskset -c 0)
        echo "bench-gate: CPU-pinning enabled (core 0 via taskset)" >&2
    else
        echo "bench-gate: BENCH_PIN=1 requested but taskset not available; running unpinned" >&2
    fi
fi

cd "${REPO_ROOT}"

"${pin_prefix[@]+"${pin_prefix[@]}"}" go test \
    -bench="${bench_regex}" \
    -benchmem \
    -benchtime="${BENCH_TIME}" \
    -count="${BENCH_COUNT}" \
    -run='^$' \
    "${packages[@]}"
