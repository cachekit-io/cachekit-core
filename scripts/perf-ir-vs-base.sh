#!/usr/bin/env bash
# Instruction-count gate against a base commit, both measured on this machine.
#
# The committed budgets (benches/perf_ir_baselines.json) hold for the machine
# and toolchain they were recorded on. Counts move with the CPU valgrind passes
# through, rustc and valgrind, so any other machine, a CI runner included, can
# only compare against figures it measured itself. This script measures the
# merge-base of HEAD and <base-ref> in a temporary worktree, then gates the
# working tree against those figures with the same toolchain. Nothing in the
# working tree is modified.
#
# Usage: scripts/perf-ir-vs-base.sh <base-ref> [--jobs <n>]
# Exits 0 when every case shared with the base passes, non-zero on a
# regression or an error.
set -euo pipefail

base_ref=${1:?usage: scripts/perf-ir-vs-base.sh <base-ref> [gate options]}
shift
for arg in "$@"; do
  case $arg in
    --case | --update | --allow-increase | --baselines)
      echo "perf-ir-vs-base: $arg is not supported here; it gates every shared case" >&2
      exit 2
      ;;
  esac
done
root=$(git rev-parse --show-toplevel)
base=$(git -C "$root" merge-base HEAD "$base_ref")
scratch=$(mktemp -d)
trap 'git -C "$root" worktree remove --force "$scratch/base" >/dev/null 2>&1 || true; rm -rf "${scratch:?}"' EXIT

gate=(cargo bench -p cachekit-core --features encryption --bench perf_ir --)
cases() { "${gate[@]}" --help | sed -n 's/^cases: //p' | tr ' ' '\n'; }

echo "== base $base: recording Ir/op on this machine"
git -C "$root" worktree add --detach "$scratch/base" "$base" >/dev/null
# --update --allow-increase on every case re-records the base's own budget
# file with this machine's figures, whatever toolchain the committed set had.
(cd "$scratch/base" && "${gate[@]}" --update --allow-increase "$@" && cases >"$scratch/base-cases")
cp "$scratch/base/benches/perf_ir_baselines.json" "$scratch/budgets.json"

echo "== head $(git -C "$root" rev-parse HEAD): gating against the base figures"
cd "$root"
cases >"$scratch/head-cases"
new=$(grep -Fvxf "$scratch/base-cases" "$scratch/head-cases" || true)
if [ -n "$new" ]; then
  echo "not gated (no base figure; new in this change): ${new//$'\n'/ }"
fi
selected=()
while read -r case; do selected+=(--case "$case"); done < <(grep -Fxf "$scratch/base-cases" "$scratch/head-cases" || true)
if [ ${#selected[@]} -eq 0 ]; then
  echo "perf-ir-vs-base: base and head share no case" >&2
  exit 2
fi
"${gate[@]}" --baselines "$scratch/budgets.json" "${selected[@]}" "$@"
