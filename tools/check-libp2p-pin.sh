#!/usr/bin/env bash
# Nim-LibP2P-Mix
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

# Verifies that `nix/deps.nix` pins the libp2p revision that
# `libp2p_mix.nimble` asks for.
#
# `nix/deps.nix` is a committed pin: every dependency is fixed to an exact
# rev + sha256. It is deliberately NOT re-derived in CI. Regenerating it runs
# `nimble lock`, which re-resolves the nimble file's open version ranges
# ("chronos >= 4.2.2", plus everything transitive via libp2p) to each
# dependency's current default-branch HEAD. Those HEADs move daily, so a
# regenerated file can never match a committed one and the check fails on
# upstream activity that has nothing to do with the PR under test.
#
# So we check the one thing a PR actually controls and that resolves
# deterministically: the libp2p tag. That catches the real mistake — bumping
# libp2p_mix.nimble without running `make refresh-deps` — while staying green
# when unrelated upstream repos move.

set -euo pipefail

NIMBLE_FILE="${1:-libp2p_mix.nimble}"
DEPS_NIX="${2:-nix/deps.nix}"
LIBP2P_URL="https://github.com/vacp2p/nim-libp2p"

for f in "$NIMBLE_FILE" "$DEPS_NIX"; do
  [[ -f "$f" ]] || { echo "error: $f not found" >&2; exit 1; }
done

# requires ... "libp2p == 2.1.4" ...
version="$(grep -oE '"libp2p[[:space:]]*==[[:space:]]*[0-9]+(\.[0-9]+)*"' "$NIMBLE_FILE" |
  head -1 | sed -E 's/.*==[[:space:]]*([0-9]+(\.[0-9]+)*)".*/\1/')"

if [[ -z "$version" ]]; then
  echo "error: no exact 'libp2p == X.Y.Z' pin found in $NIMBLE_FILE" >&2
  echo "hint: this check requires an exact libp2p version, not a range." >&2
  exit 1
fi

# Annotated tags need the ^{} deref to reach the commit; lightweight tags
# point at it directly and return nothing for ^{}.
expected="$(git ls-remote "$LIBP2P_URL" "refs/tags/v${version}^{}" | cut -f1)"
[[ -n "$expected" ]] || expected="$(git ls-remote "$LIBP2P_URL" "refs/tags/v${version}" | cut -f1)"

if [[ -z "$expected" ]]; then
  echo "error: tag v${version} not found in ${LIBP2P_URL}" >&2
  exit 1
fi

actual="$(awk '
  /^[[:space:]]*libp2p = pkgs\.fetchgit/ { found = 1 }
  found && /rev = "/ { gsub(/^.*rev = "|";.*$/, ""); print; exit }
' "$DEPS_NIX")"

if [[ -z "$actual" ]]; then
  echo "error: no libp2p entry found in $DEPS_NIX" >&2
  exit 1
fi

if [[ "$actual" != "$expected" ]]; then
  cat >&2 <<EOF
error: $DEPS_NIX does not pin the libp2p version $NIMBLE_FILE requires

  requires libp2p == $version  (tag v$version = $expected)
  $DEPS_NIX pins               $actual

Run 'make refresh-deps NIMBLE_FLAGS="-y"' and commit the regenerated $DEPS_NIX.
EOF
  exit 1
fi

echo "OK: libp2p == $version -> $expected matches $DEPS_NIX"
