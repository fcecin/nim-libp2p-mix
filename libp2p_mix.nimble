mode = ScriptMode.Verbose

packageName = "libp2p_mix"
version = "0.1.0"
author = "Status Research & Development GmbH"
description =
  "Mix protocol for nim-libp2p — anonymous routing with the Sphinx packet format"
license = "MIT"
skipDirs = @["examples", "tests"]

# nim-libp2p pinned to the master commit that merged the mix-extraction PR
# (vacp2p/nim-libp2p#2378). That commit removes `MixPubKeyBook` from
# libp2p/peerstore — required so the local definition in libp2p_mix/pool
# is unambiguous. The newer libp2p adds a git-pinned boringssl dep that
# trips nimble's default SAT solver, so the CI workflow uses
# `--solver:legacy` for `nimble setup`. Once a release including #2378
# is tagged, replace the pin with `libp2p >= <new-version>`.
requires "nim >= 2.0.0",
  "https://github.com/vacp2p/nim-libp2p.git#7e72c0d6df8dd9dbd2902915da332a109aaf7906",
  "chronicles >= 0.11.0", "chronos >= 4.2.2", "metrics", "nimcrypto >= 0.6.0",
  "bearssl >= 0.2.7", "stew >= 0.4.2", "results", "unittest2"

import os, strutils

let nimc = getEnv("NIMC", "nim") # Which nim compiler to use
let lang = getEnv("NIMLANG", "c") # Which backend (c/cpp/js)
let flags = getEnv("NIMFLAGS", "") # Extra flags for the compiler
let verbose = getEnv("V", "") notin ["", "0"]

let cfg =
  " --styleCheck:usages --styleCheck:error" & (if verbose: "" else: " --verbosity:0") &
  " --skipUserCfg -f --threads:on --opt:speed" &
  " -d:libp2p_mix_experimental_exit_is_dest"

proc runTest(filename: string, moreoptions: string = "") =
  var compileCmd = nimc & " " & lang & " " & cfg & " " & flags
  compileCmd &= " " & moreoptions

  exec compileCmd & " tests/" & filename
  exec "./tests/" & filename.toExe
  rmFile "tests/" & filename.toExe

proc buildExample(filename: string) =
  let cmd = nimc & " " & lang & " " & cfg & " " & flags & " --hints:off"
  exec cmd & " examples/" & filename
  let exeName = filename.changeFileExt("").toExe
  rmFile "examples/" & exeName

task test, "Run unit tests":
  for f in listFiles("tests"):
    let (_, name, ext) = f.splitFile
    if ext == ".nim" and name.startsWith("test_"):
      runTest(name)

task testComponent, "Run component (integration) tests":
  for f in listFiles("tests/component"):
    let (_, name, ext) = f.splitFile
    if ext == ".nim" and name.startsWith("test_"):
      runTest("component/" & name)

task testAll, "Run unit + component tests":
  exec "nimble test"
  exec "nimble testComponent"

task example, "Build and run the mix_ping example":
  buildExample("mix_ping.nim")
