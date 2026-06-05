{ pkgs }:

let
  nimVersion = "2.2.10";
  nimbleVersion = "0.22.3";

  nimbleSrc = pkgs.fetchFromGitHub {
    owner = "nim-lang";
    repo = "nimble";
    rev = "v${nimbleVersion}";
    hash = "sha256-v0RhIx6ithFJqH6ThKpyvC0JB3CBCevahhCossC+deA=";
    fetchSubmodules = true;
  };

  toolchain = pkgs.stdenv.mkDerivation {
    pname = "nim-toolchain";
    version = "${nimVersion}-nimble-${nimbleVersion}";

    src = pkgs.fetchurl {
      url = "https://nim-lang.org/download/nim-${nimVersion}.tar.xz";
      sha256 = "1mfmx103z7cfk8m5ac945zk7hf0m8i3knkyc1gqvq1j203nvfmvr";
    };

    strictDeps = true;

    buildInputs = [
      pkgs.openssl
      pkgs.pcre
      pkgs.readline
      pkgs.sqlite
    ];

    configurePhase = ''
      runHook preConfigure
      export HOME=$TMPDIR
      runHook postConfigure
    '';

    buildPhase = ''
      runHook preBuild

      sh build.sh
      bin/nim c --noNimblePath --skipUserCfg --skipParentCfg --hints:off koch
      ./koch boot -d:release --skipUserCfg --skipParentCfg --hints:off
      ./koch toolsNoExternal --skipUserCfg --skipParentCfg --hints:off

      cp -r ${nimbleSrc} nimble-${nimbleVersion}
      chmod -R u+w nimble-${nimbleVersion}
      bin/nim c \
        -d:release \
        -d:git_revision_override=v${nimbleVersion} \
        --skipUserCfg \
        --skipParentCfg \
        --noNimblePath \
        --path:nimble-${nimbleVersion}/vendor/checksums/src \
        --path:nimble-${nimbleVersion}/vendor/chronos \
        --path:nimble-${nimbleVersion}/vendor/results \
        --path:nimble-${nimbleVersion}/vendor/sat/src \
        --path:nimble-${nimbleVersion}/vendor/stew \
        --path:nimble-${nimbleVersion}/vendor/zippy/src \
        nimble-${nimbleVersion}/src/nimble.nim

      runHook postBuild
    '';

    installPhase = ''
      runHook preInstall

      mkdir -p $out/nim $out/bin
      cp -r bin compiler config dist lib tools koch nim.nimble $out/nim/
      cp nimble-${nimbleVersion}/src/nimble $out/nim/bin/nimble

      for exe in nim nimble nimsuggest nimpretty testament; do
        if [ -x "$out/nim/bin/$exe" ]; then
          ln -s "$out/nim/bin/$exe" "$out/bin/$exe"
        fi
      done

      runHook postInstall
    '';

    meta = with pkgs.lib; {
      description = "Upstream Nim ${nimVersion} with Nimble ${nimbleVersion}";
      homepage = "https://nim-lang.org/";
      license = licenses.mit;
      mainProgram = "nim";
      platforms = platforms.unix;
    };
  };
in
{
  nim = toolchain;
  nimble = toolchain;
}
