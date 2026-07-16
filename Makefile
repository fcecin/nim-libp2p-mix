.PHONY: all build deps refresh-deps clean clean-nimbledeps setup format

NIMBLE_FLAGS ?=
NPH_FILES = $(shell git ls-files '*.nim' '*.nimble' '*.nims')

RMDIR := rm -rf

all: build

setup:
	nimble setup -l $(NIMBLE_FLAGS)

# `nix/deps.nix` is a committed pin — an exact rev + sha256 per dependency —
# and `nix build` consumes it as-is. Building never regenerates it.
#
# That is deliberate: regenerating runs `nimble lock`, which re-resolves the
# open version ranges in `libp2p_mix.nimble` ("chronos >= 4.2.2", plus
# everything transitive via libp2p) to each dependency's current
# default-branch HEAD. Those HEADs move daily, so making the pin a build
# dependency meant an ordinary `make build` could silently repin the whole
# tree — which is how the committed pin kept drifting out from under CI.
# Refresh it deliberately with `make refresh-deps`, then commit the result.
#
# `nimble.lock` is an intermediate artefact of that refresh, not committed
# (see .gitignore and issue #13). The Nim-matrix CI jobs provision deps with
# `make setup NIMBLE_FLAGS="$NIMBLE_FLAGS"` and never read it.
build:
	nix build

format:
	nph $(NPH_FILES)

clean:
	$(RMDIR) nimble.lock nimbledeps nimble.paths

clean-nimbledeps:
	$(RMDIR) nimbledeps nimble.paths

# Re-resolve dependency ranges and rewrite the committed pin. Run this when
# bumping a dependency in `libp2p_mix.nimble`, then commit `nix/deps.nix`.
refresh-deps:
	$(RMDIR) nimble.lock
	nimble lock $(NIMBLE_FLAGS)
	NIMBLE_FLAGS='$(NIMBLE_FLAGS)' ./tools/gen-deps.sh nimble.lock nix/deps.nix

deps: refresh-deps
