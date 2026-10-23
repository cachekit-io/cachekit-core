#!/usr/bin/env bash
# Instruction-count gate against a base commit, both measured on this machine.
#
# The committed budgets (benches/perf_ir_baselines.json) hold for the machine
# and toolchain they were recorded on. Counts move with the CPU valgrind passes
# through, rustc and valgrind, so any other machine, a CI runner included, can
# only compare against figures it measured itself. This script measures the
# library at the merge-base of HEAD and <base-ref> in a temporary worktree,
# then gates the working tree against those figures with the same toolchain.
# Nothing in the working tree is modified.
#
# Both sides run the working tree's benches/, so they measure one workload:
# with each revision's own benches, a change that edits a fixture and keeps
# its case name would compare two different workloads under one name.
#
# Usage: scripts/perf-ir-vs-base.sh <base-ref> [--jobs <n>]
# Exits 0 when every case passes, non-zero on a regression or an error.
set -euo pipefail

base_ref=${1:?usage: scripts/perf-ir-vs-base.sh <base-ref> [--jobs <n>]}
shift
for arg in "$@"; do
  case $arg in
    --case | --update | --allow-increase | --baselines)
      echo "perf-ir-vs-base: $arg is not supported here; it gates every case" >&2
      exit 2
      ;;
  esac
done
root=$(git rev-parse --show-toplevel)
base=$(git -C "$root" merge-base HEAD "$base_ref")
scratch=$(mktemp -d)
trap 'git -C "$root" worktree remove --force "$scratch/base" >/dev/null 2>&1 || true; rm -rf "${scratch:?}"' EXIT

gate=(cargo bench -p cachekit-core --features encryption --bench perf_ir --)

echo "== base $base: recording Ir/op on this machine with the working tree's benches/"
git -C "$root" worktree add --detach "$scratch/base" "$base" >/dev/null
rm -rf "${scratch:?}/base/benches"
cp -R "$root/benches" "$scratch/base/benches"
# --update --allow-increase on every case re-records the copied budget file
# with this machine's figures, whatever toolchain the committed set had.
# The base builds into its own target dir, never the working tree's: in a
# shared one, cargo's mtime check can take the base build's newer outputs as
# fresh for the head's older sources and gate the base binary against itself.
if ! (cd "$scratch/base" && CARGO_TARGET_DIR="$scratch/base-target" "${gate[@]}" --update --allow-increase "$@"); then
  echo "perf-ir-vs-base: the working tree's benches/ could not measure the base library;" \
    "if they call API the base does not have, the change is not comparable here" >&2
  exit 2
fi
cp "$scratch/base/benches/perf_ir_baselines.json" "$scratch/budgets.json"

echo "== head $(git -C "$root" rev-parse HEAD): gating against the base figures"
cd "$root"
"${gate[@]}" --baselines "$scratch/budgets.json" "$@"
