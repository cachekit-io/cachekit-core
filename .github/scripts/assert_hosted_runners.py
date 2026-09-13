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
  - matrix indirection `runs-on: ${{ matrix.os }}` / `${{ matrix.runner }}` -> allowed
    ONLY because every matrix `os:` / `runner:` value in the file is scanned directly
    (a non-hosted value anywhere fails the whole file). ANY OTHER expression
    (`${{ matrix.platform }}`, `${{ vars.RUNNER }}`, `${{ env.POOL }}`) is a violation:
    the scanner does not resolve it, so it will not bless it.
  - object form `runs-on: { group:, labels: }` -> `group:` is rejected outright (this
    repo uses standard hosted labels, never a runner group; a hosted larger-runner
    group would be an explicit future decision that must extend this allow-list), and
    every `labels:` entry is allow-listed.
  - matrix `include` entries whose first key is `- os:` / `- runner:` (label on the
    dash line) are scanned like any other `os:` / `runner:` value.
  - a comment after `runs-on:` (`runs-on:  # note`) is not mistaken for a label.

SCOPE / what this is NOT. This runs inside the workflow, so it only protects against
*maintainer drift on a trusted branch*: a fork PR runs the fork's own copy of this
file and can simply delete the guard, so it is not a fork-PR control. The server-side
control (runner group `cachekit-private`, allows_public_repositories=false) is
LAB-1161 stage 2.

Deliberately dependency-free (stdlib only): it must behave identically on a hosted
runner and a laptop, with no PyYAML — the ubuntu-latest image does not ship it, and a
`pip install` in a merge-gating security check adds network flakiness. A focused,
fail-closed line scanner with a self-test that locks every case is the right trade.

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

# The two matrix keys that runs-on is permitted to indirect through; their values
# are scanned directly, so `runs-on: ${{ matrix.os }}` is verifiable. Any other
# expression is not resolvable by this scanner and therefore fails closed.
RESOLVABLE_EXPR = re.compile(r"^\$\{\{\s*matrix\.(os|runner)\s*\}\}$")

# A runner-label-bearing line: `runs-on:` (job key) or a matrix `os:` / `runner:`
# value, optionally on a `- ` sequence-item dash (matrix include entries).
KEY = re.compile(r"^(?P<indent>\s*)(?:-\s+)?(?P<key>runs-on|os|runner):\s*(?P<value>.*?)\s*$")
SEQ_ITEM = re.compile(r"^(?P<indent>\s*)-\s*(?P<value>.+?)\s*$")
MAP_ITEM = re.compile(r"^(?P<indent>\s*)(?P<key>group|labels):\s*(?P<value>.*?)\s*$")


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
    """Return (line_number, key, offending_value) for every non-hosted target."""
    lines = text.splitlines()
    out: list[tuple[int, str, str]] = []
    i = 0
    while i < len(lines):
        m = KEY.match(lines[i])
        if not m:
            i += 1
            continue
        key, raw = m.group("key"), m.group("value")
        value = _strip_comment(raw)

        # --- inline value present -----------------------------------------
        if value:
            if value.startswith("${{"):
                # Expressions are only meaningful (and only occur) on runs-on.
                if key == "runs-on" and not RESOLVABLE_EXPR.match(value):
                    out.append((i + 1, "runs-on (unresolvable expression)", value))
                # matrix.os / matrix.runner: verified via the os/runner scan below.
            else:
                for label in _labels_from_inline(value):
                    if _bad_label(label):
                        out.append((i + 1, key, label))
            i += 1
            continue

        # --- empty inline value: a block follows on deeper-indented lines --
        key_indent = _indent(m.group(0))
        j = i + 1
        while j < len(lines):
            if not lines[j].strip():
                j += 1
                continue
            if _indent(lines[j]) <= key_indent:
                break
            seq = SEQ_ITEM.match(lines[j])
            if seq:
                label = _unquote(_strip_comment(seq.group("value")))
                if label and not label.startswith("${{") and _bad_label(label):
                    out.append((j + 1, key, label))
                j += 1
                continue
            # object form: `runs-on:` followed by `group:` / `labels:`
            mp = MAP_ITEM.match(lines[j])
            if mp and key == "runs-on":
                sub, sval = mp.group("key"), _strip_comment(mp.group("value"))
                if sub == "group":
                    # Any runner-group target fails closed (see module docstring).
                    if sval and not sval.startswith("${{"):
                        out.append((j + 1, "runs-on.group", _unquote(sval)))
                elif sval:  # labels: [ ... ] inline
                    for label in _labels_from_inline(sval):
                        if _bad_label(label):
                            out.append((j + 1, "runs-on.labels", label))
                # labels with an empty inline value → its block items are picked
                # up by SEQ_ITEM on the following iterations of this same loop.
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
        with open(path, encoding="utf-8") as fh:
            for lineno, key, value in find_violations(fh.read()):
                print(
                    f"::error file={path},line={lineno}::runner target '{value}' on "
                    f"'{key}' is not a provably GitHub-hosted runner. Every job must "
                    f"run on ubuntu-*/macos-*/windows-*; self-hosted pools, runner "
                    f"groups, and unresolvable ${{{{ }}}} runner expressions are "
                    f"forbidden in this repo (LAB-1161 / LAB-3501)."
                )
                failed = True
    if failed:
        return 1
    print(f"OK: all runner targets across {len(files)} workflow file(s) are GitHub-hosted.")
    return 0


def _selftest() -> int:
    def v(text):
        return [val for _, _, val in find_violations(text)]

    # --- MUST FAIL: direct pool labels and future names -------------------
    assert v("    runs-on: cachekit\n") == ["cachekit"]
    assert v("    runs-on: cachekit-lean\n") == ["cachekit-lean"]
    assert v("    runs-on: self-hosted\n") == ["self-hosted"]
    assert v("    runs-on: cachekit-turbo\n") == ["cachekit-turbo"]
    assert v("    runs-on: [self-hosted, linux, x64]\n") == ["self-hosted", "linux", "x64"]
    assert v("    runs-on:\n      - self-hosted\n      - linux\n") == ["self-hosted", "linux"]
    assert v("        runner: cachekit\n") == ["cachekit"]
    assert v('        os: "self-hosted"  # quoted + comment\n') == ["self-hosted"]

    # --- MUST FAIL: the fail-open forms the expert panel found ------------
    # runner-group object form (LAB-1161 stage 2's own mechanism).
    assert v("    runs-on:\n      group: cachekit-private\n") == ["cachekit-private"]
    assert v("    runs-on:\n      group: cachekit-private\n      labels: [self-hosted]\n") == [
        "cachekit-private",
        "self-hosted",
    ]
    # A hosted-*sounding* group name is still rejected: groups are not used here.
    assert v("    runs-on:\n      group: ubuntu-big\n") == ["ubuntu-big"]
    # matrix include entry whose FIRST key is os/runner (label on the dash line).
    assert v("        include:\n          - os: cachekit\n            rust: stable\n") == ["cachekit"]
    assert v("          - runner: self-hosted\n") == ["self-hosted"]
    # indirection through a key the scanner does not resolve → fail closed.
    assert v("    runs-on: ${{ matrix.platform }}\n") == ["${{ matrix.platform }}"]
    assert v("    runs-on: ${{ vars.RUNNER }}\n") == ["${{ vars.RUNNER }}"]
    assert v("    runs-on: ${{ env.POOL }}\n") == ["${{ env.POOL }}"]

    # --- MUST PASS: hosted labels, variants, and verifiable indirection ---
    assert v("    runs-on: ubuntu-latest\n") == []
    assert v("    runs-on: macos-latest\n") == []
    assert v("    runs-on: windows-latest\n") == []
    assert v("    runs-on: ubuntu-24.04\n") == []
    assert v("    runs-on: ubuntu-24.04-arm\n") == []
    assert v("    runs-on: [ubuntu-latest]\n") == []
    assert v("    runs-on: ${{ matrix.os }}\n") == []
    assert v("    runs-on: ${{ matrix.runner }}\n") == []
    assert v("        os:\n          - ubuntu-latest\n          - macos-latest\n") == []
    # A comment after runs-on before a block list must not be read as a label.
    assert v("    runs-on:  # pick per matrix\n      - ubuntu-latest\n") == []
    # A comment line that merely mentions a pool name must not trip the scanner.
    assert v("    # runs-on: cachekit was the old value\n    runs-on: ubuntu-latest\n") == []
    # runs-on via matrix.os, with the matrix defining only hosted os values.
    assert v(
        "    runs-on: ${{ matrix.os }}\n"
        "    strategy:\n      matrix:\n        include:\n"
        "          - os: ubuntu-latest\n          - os: macos-latest\n"
    ) == []

    print("selftest OK")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv[1:]:
        sys.exit(_selftest())
    sys.exit(main())
