# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## The peer pool of a MixProtocol.
##
## `MixPool` is the base class. A subclass supplies two primitives, `readPeer`
## and `listPeerIds`, and can override `selectReplyPeer`. The procs in this module
## are the behavior that every pool shares. `pool.nim` has `MixNodePool`, the
## stock pool on a libp2p peer store. A host with its own peer store and its
## own policies subclasses `MixPool` instead.

{.push raises: [].}

import std/sets
import chronos, results
import libp2p/[peerid, multiaddress, crypto/crypto, crypto/secp]
import libp2p/crypto/curve25519
import ./mix_node
import ./multiaddr as mix_multiaddr

export results, mix_node.MixPubInfo

type MixPeerRecord* = object
  ## What a pool knows about one peer. An empty record means an unknown or
  ## excluded peer. Addresses come in preference order, best first.
  mixPubKey*: Curve25519Key
  publicKey*: PublicKey
  addresses*: seq[MultiAddress]

type MixPool* = ref object of RootObj ## The peers a MixProtocol routes through.
  rng*: Rng ## Drives the random selections below. The subclass sets it.

method readPeer*(
    pool: MixPool, peerId: PeerId
): Result[MixPeerRecord, string] {.base, gcsafe, raises: [].} =
  ## The record of one peer. An error means the pool could not answer.
  raiseAssert "a MixPool subclass must implement readPeer"

method listPeerIds*(
    pool: MixPool
): Result[seq[PeerId], string] {.base, gcsafe, raises: [].} =
  ## The ID of every peer in the pool. A repeated ID counts once.
  raiseAssert "a MixPool subclass must implement listPeerIds"

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

proc usablePeer*(pool: MixPool, peerId: PeerId): Result[Opt[MixPubInfo], string] =
  ## Read one peer and check it as a route hop.
  ok((?pool.readPeer(peerId)).usablePeer(peerId))

proc count*(pool: MixPool, exclude: openArray[PeerId]): Result[int, string] =
  ## Count the usable peers that are not excluded.
  var seen: HashSet[PeerId]
  var count = 0
  for peerId in ?pool.listPeerIds():
    if peerId in exclude or seen.containsOrIncl(peerId):
      continue
    if (?pool.usablePeer(peerId)).isSome:
      count.inc()
  ok(count)

proc selectRandomNodes*(
    pool: MixPool, count: int, exclude: openArray[PeerId]
): Result[seq[MixPubInfo], string] =
  ## Select `count` distinct usable peers at random, in random order.
  if count < 0:
    return err("mix peer count must not be negative")
  if count == 0:
    return ok(newSeq[MixPubInfo]())
  doAssert not pool.rng.isNil, "MixPool has no RNG"
  var seen: HashSet[PeerId]
  var selected: seq[MixPubInfo]
  var usable = 0
  for peerId in ?pool.listPeerIds():
    if peerId in exclude or seen.containsOrIncl(peerId):
      continue
    (?pool.usablePeer(peerId)).withValue(info):
      usable.inc()
      # Reservoir sampling. Each usable peer ends in the sample with the same
      # probability, whatever the order of the IDs.
      if selected.len < count:
        selected.add(info)
      else:
        let slot = pool.rng.rand(0, usable - 1)
        if slot < count:
          selected[slot] = info
  if selected.len < count:
    return err("not enough usable mix nodes for a path")
  # The reservoir is a subset in arrival order. Shuffle it for a random path.
  for i in countdown(selected.high, 1):
    let j = pool.rng.rand(0, i)
    swap(selected[i], selected[j])
  ok(selected)

method selectReplyPeer*(
    pool: MixPool, excluded: seq[PeerId]
): Future[Result[PeerId, string]] {.base, async: (raises: [CancelledError]).} =
  ## The final peer of a reply path, the hop that delivers the reply to this
  ## node. The default takes one usable peer at random. A host that knows its
  ## connectivity overrides this, for example to prefer a connected peer.
  let peers = pool.selectRandomNodes(1, excluded).valueOr:
    return err(error)
  return ok(peers[0].peerId)
