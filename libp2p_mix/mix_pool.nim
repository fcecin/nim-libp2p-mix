# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## The peer pool of a MixProtocol.
##
## `MixPool` is the base type. A derived type supplies two primitives, `readPeer`
## and `listPeerIds`, and can override `selectReplyPeer`. The procs in this module
## are the behavior that every pool shares. `pool.nim` has `MixNodePool`, the
## stock pool on a libp2p peer store. A host with its own peer store and its
## own policies derives a type from `MixPool` instead.

{.push raises: [].}

import std/sets
import chronicles, chronos, metrics, results
import libp2p/[peerid, multiaddress, crypto/crypto, crypto/secp]
import libp2p/crypto/curve25519
import ./mix_metrics, ./mix_node
import ./multiaddr as mix_multiaddr

logScope:
  topics = "libp2p mix pool"

export results, mix_node.MixPubInfo

type
  MixPoolErrorKind* = enum
    PoolUnavailable ## The pool could not answer. Also the zero value of the type.
    LowPool ## The pool answered with too few usable peers for a path.

  MixPoolError* = object
    ## A pool selection error. `kind` distinguishes too few usable peers from
    ## pool failure, and `msg` gives the cause.
    kind*: MixPoolErrorKind
    msg*: string

func unavailable*(T: type MixPoolError, msg: string): T =
  ## An error when the pool cannot answer.
  T(kind: PoolUnavailable, msg: msg)

func lowPool*(T: type MixPoolError, msg: string): T =
  ## An error for too few usable peers.
  T(kind: LowPool, msg: msg)

type MixPeerRecord* = object
  ## What a pool knows about one peer. An empty record means an unknown or
  ## excluded peer. Addresses come in preference order, best first.
  mixPubKey*: Curve25519Key
  publicKey*: PublicKey
  addresses*: seq[MultiAddress]

type MixPool* = ref object of RootObj ## The peers a MixProtocol routes through.

method readPeer*(
    pool: MixPool, peerId: PeerId
): Result[MixPeerRecord, string] {.base, gcsafe, raises: [].} =
  ## The record of one peer. An error means the pool could not answer.
  raiseAssert "a derived MixPool must implement readPeer"

method listPeerIds*(
    pool: MixPool
): Result[seq[PeerId], string] {.base, gcsafe, raises: [].} =
  ## The ID of every peer in the pool. A repeated ID counts once.
  raiseAssert "a derived MixPool must implement listPeerIds"

proc usablePeer*(record: MixPeerRecord, peerId: PeerId): Opt[MixPubInfo] =
  ## The peer as a route hop, or none. A hop needs both keys and one address
  ## that the wire format can encode. The first such address wins.
  if record.mixPubKey == default(Curve25519Key) or record.publicKey.scheme != Secp256k1:
    return Opt.none(MixPubInfo)
  for address in record.addresses:
    if mix_multiaddr.multiAddrToBytes(peerId, address).isOk:
      return Opt.some(
        MixPubInfo.init(peerId, address, record.mixPubKey, record.publicKey.skkey)
      )
  Opt.none(MixPubInfo)

proc usablePeer*(pool: MixPool, peerId: PeerId): Result[Opt[MixPubInfo], MixPoolError] =
  ## Read one peer and check it as a route hop.
  let record = pool.readPeer(peerId).valueOr:
    return
      err(MixPoolError.unavailable("readPeer failed for " & $peerId & ": " & error))
  ok(record.usablePeer(peerId))

proc countUsable*(
    pool: MixPool, exclude: openArray[PeerId]
): Result[int, MixPoolError] =
  ## Count the usable peers that are not excluded. A peer counts once.
  let ids = pool.listPeerIds().valueOr:
    return err(MixPoolError.unavailable("listPeerIds failed: " & error))
  var seen: HashSet[PeerId]
  var count = 0
  for peerId in ids:
    if peerId in exclude or seen.containsOrIncl(peerId):
      continue
    if (?pool.usablePeer(peerId)).isSome:
      count.inc()
  ok(count)

proc selectRandomNodes*(
    pool: MixPool, rng: Rng, count: int, exclude: openArray[PeerId]
): Result[seq[MixPubInfo], MixPoolError] =
  ## Shuffle candidate IDs, then read until `count` distinct usable peers fill
  ## the path. Count each peer skipped for missing keys or an unencodable address.
  if count < 0:
    return err(MixPoolError.unavailable("mix peer count must not be negative"))
  if count == 0:
    return ok(newSeq[MixPubInfo]())
  doAssert not rng.isNil, "selectRandomNodes needs an RNG"
  var seen: HashSet[PeerId]
  let ids = pool.listPeerIds().valueOr:
    return err(MixPoolError.unavailable("listPeerIds failed: " & error))
  var candidates: seq[PeerId]
  for peerId in ids:
    if peerId in exclude or seen.containsOrIncl(peerId):
      continue
    candidates.add(peerId)
  # `pick` of every ID is a uniform shuffle. The libp2p `shuffle` is biased.
  let order = rng.pick(candidates, candidates.len).valueOr:
    return err(
      MixPoolError.lowPool(
        "not enough usable mix nodes for a path, usable: 0, needed: " & $count
      )
    )
  var usable: seq[MixPubInfo]
  for peerId in order:
    let info = (?pool.usablePeer(peerId)).valueOr:
      mix_messages_error.inc(labelValues = ["Pool", "INVALID_MIX_INFO"])
      trace "Skipped mix peer without keys or an encodable address", peerId
      continue
    usable.add(info)
    if usable.len == count:
      return ok(usable)
  err(
    MixPoolError.lowPool(
      "not enough usable mix nodes for a path, usable: " & $usable.len & ", needed: " &
        $count
    )
  )

method selectReplyPeer*(
    pool: MixPool, rng: Rng, excluded: seq[PeerId]
): Future[Result[PeerId, MixPoolError]] {.base, async: (raises: [CancelledError]).} =
  ## The final peer of a reply path, the hop that delivers the reply to this
  ## node. The default takes one usable peer at random. A host that knows its
  ## connectivity overrides this, for example to prefer a connected peer. A
  ## hook must return promptly and stop when cancelled. `MixProtocol` cancels a
  ## selection that exceeds its `replyPeerTimeout` and fails the send.
  let peers = pool.selectRandomNodes(rng, 1, excluded).valueOr:
    return err(
      MixPoolError(
        kind: error.kind,
        msg: "issue in selectReplyPeer when calling selectRandomNodes: " & error.msg,
      )
    )
  return ok(peers[0].peerId)
