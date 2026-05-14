.PHONY: all build deps clean

all: build

# --solver:legacy is required while libp2p_mix.nimble pins libp2p to a git
# commit (nimble's default SAT solver can't resolve transitive git pins).
# Drop the flag once libp2p is pinned by version.
nimble.lock: libp2p_mix.nimble
	nimble --solver:legacy lock

nix/deps.nix: nimble.lock tools/gen-deps.sh
	./tools/gen-deps.sh nimble.lock nix/deps.nix

deps: nix/deps.nix

build: deps
	nix build

clean:
	$(RM) nimble.lock nix/deps.nix
