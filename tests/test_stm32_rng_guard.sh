#!/bin/sh

set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/libngu-rng-guard.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

mkdir -p "$tmp_dir/py"
: > "$tmp_dir/py/runtime.h"
: > "$tmp_dir/py/mperrno.h"

preprocess_random() {
    "${CC:-cc}" -E -U__linux__ -I"$tmp_dir" -I"$repo_dir/ngu" \
        -DMICROPY_PY_STM "$@" "$repo_dir/ngu/random.c" >/dev/null 2>&1
}

expect_pass() {
    label=$1
    shift
    if ! preprocess_random "$@"; then
        echo "FAIL: $label should pass"
        exit 1
    fi
}

expect_fail() {
    label=$1
    shift
    if preprocess_random "$@"; then
        echo "FAIL: $label should fail"
        exit 1
    fi
}

expect_fail "missing MicroPython RNG configuration"
expect_fail "disabled stock RNG without a board provider" \
    -DMICROPY_HW_ENABLE_RNG=0
expect_fail "false board-provider assertion" \
    -DMICROPY_HW_ENABLE_RNG=0 -DNGU_RNG_GET_IS_HARDWARE=0
expect_pass "enabled stock hardware RNG" \
    -DMICROPY_HW_ENABLE_RNG=1
expect_pass "explicit board hardware RNG provider" \
    -DMICROPY_HW_ENABLE_RNG=0 -DNGU_RNG_GET_IS_HARDWARE=1

echo "PASS: STM32 hardware RNG compile-time guard"
