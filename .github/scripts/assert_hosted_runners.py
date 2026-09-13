#!/usr/bin/env python3
"""Fail if any workflow job could run on a non-GitHub-hosted runner.

This is an ALLOW-LIST that FAILS CLOSED: every job's `runs-on` must resolve to a
known GitHub-hosted label family (`ubuntu-*`, `macos-*`, `windows-*`). Anything
the scanner cannot *prove* is hosted — `cachekit`, `self-hosted`, a future pool
label nobody has invented yet, a runner-group object, or a `${{ }}` expression it
can't resolve — is a violation. A deny-list of today's bad names would fail open
the day someone adds a new one, or reformats the drift into a shape the deny-list
doesn't grep (Alaya 999a8af5, selecta PR #72 lesson).

Forms handled, and how each stays fail-closed:
  - scalar / inline `[a, b]` / block-sequence `runs-on` -> every label allow-listed.
    A block list may sit at the key's own indent (k8s style) or deeper; comment lines
    inside it are skipped, not treated as its end. Keys may be quoted or carry a space
    before the colon (`"runs-on" :`) — the same key to YAML, so the same key here.
  - matrix indirection: the ONE blessed expression is a complete scalar
    `runs-on: ${{ matrix.os }}` or `${{ matrix.runner }}` (quotes optional), allowed
    ONLY because every matrix `os:` / `runner:` value in the file is scanned directly
    (a non-hosted value anywhere fails the whole file). EVERY other `${{ }}` in a
    runner-target position is a violation — e.g. `os: ${{ vars.POOL }}` would launder
    a self-hosted pool through the blessed indirection.
  - `matrix:` / `include:` must be static block mappings. A generated matrix
    (`matrix: ${{ fromJSON(…) }}`) or a flow mapping (`matrix: {os: […]}`) hides its
    `os:` values from the scanner, so any inline value on those keys is a violation.
    Accepted false positive: this fires on ANY `matrix:`/`include:` key with an inline
    value, e.g. an action input named `include:` — cheaper than tracking `strategy:`
    scope; write such inputs in block form.
  - flow mappings: a `{ … }` where YAML would put one (`- {`, `key: {`, a bare `{`)
    that carries `runs-on:` / `os:` / `runner:` — or a reusable-workflow `uses:` — at
    any depth (`- { os: cachekit, rust: stable }`, `strategy: { matrix: { os: […] } }`,
    `jobs: { build: { runs-on: … } }`) is rejected outright: a line scanner cannot see
    inside a flow mapping, so it does not pretend to. A YAML anchor or tag before the
    brace (`- &x { os: … }`) does not hide it. A single-line JS object literal inside a
    `script: |` step or a jq program in `run:` does not start a YAML value, so it is
    not mistaken for one; a multi-line literal with `os:` on its own line does trip
    the scanner — accepted, rename the property or keep the literal on one line.
  - object form `runs-on: { group:, labels: }` -> `group:` is rejected outright,
    whatever its value (this repo uses standard hosted labels, never a runner group; a
    hosted larger-runner group would be an explicit future decision that must extend
    this allow-list), and every `labels:` entry is allow-listed.
  - inside any `runs-on:` / `os:` / `runner:` block, a line that is not a `- item` (or,
    for runs-on, `group:` / `labels:`) is a shape this scanner cannot verify — a
    plain-scalar or `[…]` continuation line, a nested mapping — and is a violation.
    Write the value inline instead.
  - a job-level `uses:` of a REMOTE reusable workflow runs that workflow's jobs on this
    repo's runner pool with a `runs-on` this scanner cannot see -> violation, as is a
    `uses:` whose value is not inline (`uses: >-`). Local callees
    (`./.github/workflows/…`) are scanned like any other file.
  - the top-level `on:` block (triggers, `workflow_dispatch` inputs) is skipped whole:
    nothing under it selects a runner, and an input named `os:` / `runner:` would
    otherwise be misread as a matrix key.
  - matrix `include` entries whose first key is `- os:` / `- runner:` (label on the
    dash line) are scanned like any other `os:` / `runner:` value.
  - a comment after `runs-on:` (`runs-on:  # note`) is not mistaken for a label.

SCOPE / what this is NOT. This runs inside the workflow, so it only protects against
*maintainer drift on a trusted branch*: a fork PR runs the fork's own copy of this
file and can simply delete the guard, so it is not a fork-PR control. The server-side
control (runner group `cachekit-private`, allows_public_repositories=false) is
LAB-1161 stage 2. Nor does it defend its own workflow (`runner-guard.yml`) against an
`if: false` — that is branch protection's job (required status check + CODEOWNERS).

Deliberately dependency-free (stdlib only): it must behave identically on a hosted
runner and a laptop, with no PyYAML — the ubuntu-latest image does not ship it, and a
`pip install` in a merge-gating security check adds network flakiness. A focused,
fail-closed line scanner with a self-test that locks every case is the right trade.

Output is GitHub Actions workflow commands (`::error file=…::`), which the runner
parses off the raw output stream — that is why this script prints rather than logs.

Run:  python3 .github/scripts/assert_hosted_runners.py
Test: python3 .github/scripts/assert_hosted_runners.py --selftest
"""

from __future__ import annotations

import glob
import re
import sys

# GitHub-hosted label families. Versioned and ARM variants are allowed
# (ubuntu-24.04, macos-14, ubuntu-24.04-arm, windows-2022, *-latest, …).
HOSTED = re.compile(r"^(ubuntu|macos|windows)-[a-z0-9._-]+$")

# The ONE expression this scanner blesses, and only as the complete scalar value of
# `runs-on`: the two matrix keys whose values are scanned directly below, which is
# what makes the indirection verifiable. Every other expression fails closed.
RESOLVABLE_EXPR = re.compile(r"^\$\{\{\s*matrix\.(os|runner)\s*\}\}$")

# Lines this scanner acts on: a runner-label-bearing key (`runs-on:`, matrix `os:` /
# `runner:`, optionally on a `- ` dash), the `matrix:` / `include:` key whose block
# those values must live in, and `uses:` (reusable workflows). Quoted keys and a
# space before the colon are the same key to YAML.
KEY = re.compile(
    r"^(?P<indent>\s*)(?:-\s+)?(?P<q>[\"']?)(?P<key>runs-on|os|runner|matrix|include|uses)(?P=q)"
    r"\s*:\s*(?P<value>.*?)\s*$"
)
SEQ_ITEM = re.compile(r"^(?P<indent>\s*)-\s*(?P<value>.+?)\s*$")
MAP_ITEM = re.compile(r"^(?P<indent>\s*)(?P<key>group|labels):\s*(?P<value>.*?)\s*$")
# The top-level trigger block; nothing under it can select a runner.
ON_BLOCK = re.compile(r"^[\"']?on[\"']?\s*:\s*(?:#.*)?$")
# A flow mapping where YAML would put one (`- {`, `key: {`, bare `{`) — not a JS
# object literal in `script: |` nor a jq program in `run:` …
FLOW_START = re.compile(r"^\s*(?:-\s+)?(?:[\"']?[\w.-]+[\"']?\s*:\s*)?(?:[&!]\S+\s+)?\{")
# … that carries a runner-target key, or a reusable-workflow `uses:`, at any depth.
FLOW_KEY = re.compile(
    r"[{,]\s*[\"']?(?:runs-on|os|runner)[\"']?\s*:"
    r"|[{,]\s*[\"']?uses[\"']?\s*:\s*[^,}\s]*\.github/workflows/"
)


def _strip_comment(text: str) -> str:
    """Remove a `# …` comment (whole-line or trailing) and surrounding space."""
    return re.sub(r"(?:^|\s)#.*$", "", text).strip()


def _unquote(token: str) -> str:
    token = token.strip()
    if len(token) >= 2 and token[0] in "\"'" and token[-1] == token[0]:
        token = token[1:-1]
    return token.strip()


def _labels_from_inline(value: str) -> list[str]:
    """Label tokens from an inline scalar or `[a, b]` list (comments stripped)."""
    value = _strip_comment(value)
    if value.startswith("[") and value.endswith("]"):
        return [_unquote(t) for t in value[1:-1].split(",") if _unquote(t)]
    token = _unquote(value)
    return [token] if token else []


def _bad_label(label: str) -> bool:
    """True if this concrete label is not a known hosted label."""
    return HOSTED.match(label) is None


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def find_violations(text: str) -> list[tuple[int, str, str]]:
    """Return (line_number, what, offending_value) for every non-hosted target.

    `what` is the field name, with a parenthesised reason when the field's shape,
    not its label, is the problem (e.g. `matrix (not a static block)`).
    """
    lines = text.splitlines()
    out: list[tuple[int, str, str]] = []
    i = 0
    while i < len(lines):
        if ON_BLOCK.match(lines[i]):
            i += 1
            while i < len(lines) and (not lines[i].strip() or lines[i][0] in " \t#"):
                i += 1
            continue
        m = KEY.match(lines[i])
        if not m:
            stripped = _strip_comment(lines[i])
            if FLOW_START.match(stripped) and FLOW_KEY.search(stripped):
                out.append((i + 1, "flow mapping (unscannable)", stripped))
            i += 1
            continue
        key, raw = m.group("key"), m.group("value")
        value = _strip_comment(raw)

        if key == "uses":
            v = _unquote(value)
            if not v or v[0] in ">|":
                out.append((i + 1, "uses (unverifiable form)", v))
            elif ".github/workflows/" in v and not v.startswith("./"):
                out.append((i + 1, "uses (remote reusable workflow)", v))
            i += 1
            continue

        # An inline value here hides os:/runner: from the scan → blessing unearned.
        if key in ("matrix", "include"):
            if value:
                out.append((i + 1, f"{key} (not a static block)", value))
            i += 1
            continue

        # --- inline value present -----------------------------------------
        if value:
            # Only the blessed runs-on scalar (RESOLVABLE_EXPR) escapes _bad_label.
            if not (key == "runs-on" and RESOLVABLE_EXPR.match(_unquote(value))):
                for label in _labels_from_inline(value):
                    if _bad_label(label):
                        out.append((i + 1, key, label))
            i += 1
            continue

        # --- empty inline value: a block follows -----------------------------
        # Items may sit deeper OR at the key's own indent (k8s style) — unless the
        # key was itself a `- ` item, when a same-indent dash is a sibling, not ours.
        key_indent = _indent(m.group(0))
        on_dash = m.group(0).lstrip().startswith("-")
        j = i + 1
        while j < len(lines):
            if not lines[j].strip() or lines[j].lstrip().startswith("#"):
                j += 1
                continue
            ind = _indent(lines[j])
            if ind < key_indent or (ind == key_indent and (on_dash or not SEQ_ITEM.match(lines[j]))):
                break
            seq = SEQ_ITEM.match(lines[j])
            if seq:
                # An expression as a list entry is unresolvable → _bad_label rejects it.
                label = _unquote(_strip_comment(seq.group("value")))
                if label and _bad_label(label):
                    out.append((j + 1, key, label))
                j += 1
                continue
            # object form: `runs-on:` followed by `group:` / `labels:`
            mp = MAP_ITEM.match(lines[j])
            if mp and key == "runs-on":
                sub, sval = mp.group("key"), _strip_comment(mp.group("value"))
                if sub == "group":
                    # Any runner-group target fails closed, expression or not
                    # (see module docstring).
                    out.append((j + 1, "runs-on.group", _unquote(sval)))
                elif sval:  # labels: [ ... ] inline
                    for label in _labels_from_inline(sval):
                        if _bad_label(label):
                            out.append((j + 1, "runs-on.labels", label))
                # labels with an empty inline value → its block items are picked
                # up by SEQ_ITEM on the following iterations of this same loop.
            else:
                # Not a `- item`, not runs-on group:/labels: → a shape this scanner
                # cannot verify (scalar or `[…]` continuation, nested mapping).
                out.append((j + 1, f"{key} (unrecognised block form)", _strip_comment(lines[j])))
            j += 1
        i = j
    return out


def main() -> int:
    files = sorted(
        glob.glob(".github/workflows/*.yml") + glob.glob(".github/workflows/*.yaml")
    )
    if not files:
        print("::error::no workflow files found under .github/workflows/", file=sys.stderr)
        return 1
    failed = False
    for path in files:
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        except (OSError, UnicodeDecodeError) as exc:
            # Unreadable is unverifiable: fail closed, but keep scanning the rest.
            print(f"::error file={path}::cannot read workflow file: {exc}", file=sys.stderr)
            failed = True
            continue
        for lineno, what, value in find_violations(text):
            print(
                f"::error file={path},line={lineno}::{what}: '{value}' is not provably "
                f"GitHub-hosted. Every job must run on ubuntu-*/macos-*/windows-* as a "
                f"plain scalar, `[a, b]`, block list, or `${{{{ matrix.os }}}}` over a "
                f"static block matrix; self-hosted pools, runner groups, other ${{{{ }}}} "
                f"expressions, flow mappings, generated matrices and remote reusable "
                f"workflows fail closed (LAB-1161 / LAB-3501; see the docstring of "
                f".github/scripts/assert_hosted_runners.py)."
            )
            failed = True
    if failed:
        return 1
    print(f"OK: all runner targets across {len(files)} workflow file(s) are GitHub-hosted.")
    return 0


# (workflow snippet, expected offending values). Table-driven rather than `assert`
# so the self-test cannot be silently neutered by `python3 -O` / PYTHONOPTIMIZE.
_CASES: list[tuple[str, list[str]]] = [
    # --- MUST FAIL: direct pool labels and future names -------------------
    ("    runs-on: cachekit\n", ["cachekit"]),
    ("    runs-on: cachekit-lean\n", ["cachekit-lean"]),
    ("    runs-on: self-hosted\n", ["self-hosted"]),
    ("    runs-on: cachekit-turbo\n", ["cachekit-turbo"]),
    ("    runs-on: [self-hosted, linux, x64]\n", ["self-hosted", "linux", "x64"]),
    ("    runs-on:\n      - self-hosted\n      - linux\n", ["self-hosted", "linux"]),
    ("        runner: cachekit\n", ["cachekit"]),
    ('        os: "self-hosted"  # quoted + comment\n', ["self-hosted"]),
    # --- MUST FAIL: the fail-open forms the expert panel found ------------
    # runner-group object form (LAB-1161 stage 2's own mechanism).
    ("    runs-on:\n      group: cachekit-private\n", ["cachekit-private"]),
    (
        "    runs-on:\n      group: cachekit-private\n      labels: [self-hosted]\n",
        ["cachekit-private", "self-hosted"],
    ),
    # A hosted-*sounding* group name is still rejected: groups are not used here.
    ("    runs-on:\n      group: ubuntu-big\n", ["ubuntu-big"]),
    # matrix include entry whose FIRST key is os/runner (label on the dash line).
    ("        include:\n          - os: cachekit\n            rust: stable\n", ["cachekit"]),
    ("          - runner: self-hosted\n", ["self-hosted"]),
    # indirection through a key the scanner does not resolve → fail closed.
    ("    runs-on: ${{ matrix.platform }}\n", ["${{ matrix.platform }}"]),
    ("    runs-on: ${{ vars.RUNNER }}\n", ["${{ vars.RUNNER }}"]),
    ("    runs-on: ${{ env.POOL }}\n", ["${{ env.POOL }}"]),
    # --- MUST FAIL: expressions anywhere but the one blessed runs-on scalar --
    # (Kody critical / CodeRabbit on PR #76.) An expression as the os:/runner:
    # VALUE would launder a self-hosted pool through `runs-on: ${{ matrix.os }}`.
    ("        os: ${{ vars.POOL }}\n", ["${{ vars.POOL }}"]),
    (
        "    runs-on: ${{ matrix.os }}\n    strategy:\n      matrix:\n"
        "        os: ${{ fromJSON(inputs.oses) }}\n",
        ["${{ fromJSON(inputs.oses) }}"],
    ),
    # …as a block-sequence entry, as runs-on.group, or list-wrapped.
    ("    runs-on:\n      - ${{ vars.RUNNER }}\n", ["${{ vars.RUNNER }}"]),
    ("    runs-on:\n      group: ${{ vars.GROUP }}\n", ["${{ vars.GROUP }}"]),
    ("    runs-on: [${{ matrix.os }}]\n", ["${{ matrix.os }}"]),
    # A generated or flow-form matrix hides its os: values → the blessing is unearned.
    (
        "    runs-on: ${{ matrix.os }}\n    strategy:\n"
        "      matrix: ${{ fromJSON(needs.gen.outputs.matrix) }}\n",
        ["${{ fromJSON(needs.gen.outputs.matrix) }}"],
    ),
    ("        include: ${{ fromJSON(inputs.include) }}\n", ["${{ fromJSON(inputs.include) }}"]),
    ("      matrix: {os: [cachekit]}\n", ["{os: [cachekit]}"]),
    # --- MUST FAIL: shapes the panel review of PR #76 found skipped ----------
    # Flow mappings anywhere: the standard Rust cross-compile include idiom, a
    # compact strategy, a whole job in flow form (scalar, group object, alias, uses).
    (
        "        include:\n          - { os: cachekit, rust: stable }\n",
        ["- { os: cachekit, rust: stable }"],
    ),
    (
        "    strategy: { fail-fast: false, matrix: { os: [ubuntu-latest, cachekit] } }\n",
        ["strategy: { fail-fast: false, matrix: { os: [ubuntu-latest, cachekit] } }"],
    ),
    ("jobs: {build: {runs-on: cachekit}}\n", ["jobs: {build: {runs-on: cachekit}}"]),
    (
        "jobs: {build: {runs-on: {group: cachekit-private}}}\n",
        ["jobs: {build: {runs-on: {group: cachekit-private}}}"],
    ),
    ("jobs: {build: {runs-on: *pool}}\n", ["jobs: {build: {runs-on: *pool}}"]),
    (
        "jobs: {ci: {uses: org/repo/.github/workflows/ci.yml@main}}\n",
        ["jobs: {ci: {uses: org/repo/.github/workflows/ci.yml@main}}"],
    ),
    ('          - { "os": cachekit, rust: stable }\n', ['- { "os": cachekit, rust: stable }']),
    ("          - &x { os: cachekit }\n", ["- &x { os: cachekit }"]),  # anchor before the brace
    # Quoted key / space before the colon: the same key to YAML.
    ('    "runs-on": cachekit\n', ["cachekit"]),
    ("    runs-on : cachekit\n", ["cachekit"]),
    (
        "    runs-on: ${{ matrix.os }}\n    strategy:\n      matrix:\n        os : [cachekit]\n",
        ["cachekit"],
    ),
    # Block list at the key's own indent (k8s style) — was read as end-of-block.
    ("    runs-on:\n    - self-hosted\n", ["self-hosted"]),
    (
        "    runs-on: ${{ matrix.os }}\n    strategy:\n      matrix:\n        os:\n        - cachekit\n",
        ["cachekit"],
    ),
    # A column-0 commented-out entry must not end the block early.
    ("    runs-on:\n#      - ubuntu-latest\n      - self-hosted\n", ["self-hosted"]),
    # Continuation lines the scanner cannot verify (prettier emits the `[…]` one).
    ("    runs-on:\n      cachekit\n", ["cachekit"]),
    ("    runs-on:\n      [self-hosted, linux]\n", ["[self-hosted, linux]"]),
    ("    runs-on:\n      labels:\n        [self-hosted]\n", ["[self-hosted]"]),
    # Remote reusable workflow: its runs-on is invisible here but runs on our pool.
    (
        "    uses: cachekit-io/tooling/.github/workflows/ci.yml@main\n",
        ["cachekit-io/tooling/.github/workflows/ci.yml@main"],
    ),
    ("    uses: >-\n      org/repo/.github/workflows/ci.yml@main\n", [">-"]),
    ("    uses:\n      org/repo/.github/workflows/ci.yml@main\n", [""]),
    # The on: block is skipped, but jobs after it are still scanned.
    (
        "on:\n  workflow_dispatch:\n    inputs:\n      os:\n        type: choice\n"
        "        options: [ubuntu-latest]\njobs:\n  b:\n    runs-on: cachekit\n",
        ["cachekit"],
    ),
    # --- MUST PASS: hosted labels, variants, and verifiable indirection ---
    ("    runs-on: ubuntu-latest\n", []),
    ("    runs-on: macos-latest\n", []),
    ("    runs-on: windows-latest\n", []),
    ("    runs-on: ubuntu-24.04\n", []),
    ("    runs-on: ubuntu-24.04-arm\n", []),
    ("    runs-on: [ubuntu-latest]\n", []),
    ("    runs-on: ${{ matrix.os }}\n", []),
    ("    runs-on: ${{ matrix.runner }}\n", []),
    ('    runs-on: "${{ matrix.os }}"\n', []),  # quotes are transparent, as for labels
    ("        os:\n          - ubuntu-latest\n          - macos-latest\n", []),
    ("    runs-on:\n    - ubuntu-latest\n", []),  # k8s-style same-indent list
    ("    runs-on:\n      labels:\n        - ubuntu-latest\n", []),  # object form, block labels
    # A comment after runs-on before a block list must not be read as a label.
    ("    runs-on:  # pick per matrix\n      - ubuntu-latest\n", []),
    # A comment line that merely mentions a pool name must not trip the scanner.
    ("    # runs-on: cachekit was the old value\n    runs-on: ubuntu-latest\n", []),
    # runs-on via matrix.os, with a static block matrix defining only hosted values.
    (
        "    runs-on: ${{ matrix.os }}\n"
        "    strategy:\n      matrix:\n        include:\n"
        "          - os: ubuntu-latest\n          - os: macos-latest\n",
        [],
    ),
    # Local reusable workflow (quoted or not) and ordinary step actions are not remote callees.
    ("    uses: ./.github/workflows/ci.yml\n", []),
    ('    uses: "./.github/workflows/ci.yml"\n', []),
    ("      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6\n", []),
    # A workflow_dispatch input named os/runner lives under on:, not in a matrix.
    (
        '"on":\n  workflow_dispatch:\n    inputs:\n      runner:\n        description: x\n'
        "        required: false\n",
        [],
    ),
    # JS object literals in github-script and jq programs in run: are not YAML flow mappings.
    ("          script: |\n            const payload = { os: process.platform };\n", []),
    ("            core.setOutput('meta', JSON.stringify({ runner: process.env.RUNNER_NAME }));\n", []),
    ("      - run: jq -n --arg os \"$RUNNER_OS\" '{os: $os, runner: .r}'\n", []),
]


def _selftest() -> int:
    failed = False
    for text, expected in _CASES:
        got = [val for _, _, val in find_violations(text)]
        if got != expected:
            print(f"::error::selftest {text!r}: expected {expected}, got {got}", file=sys.stderr)
            failed = True
    if failed:
        return 1
    print(f"selftest OK ({len(_CASES)} cases)")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv[1:]:
        sys.exit(_selftest())
    sys.exit(main())
