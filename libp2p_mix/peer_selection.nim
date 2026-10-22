# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Mix key checks, wire-address selection and random peer selection.

{.push raises: [].}

import std/sets
import results
import libp2p/[peerid, multiaddress, crypto/crypto, crypto/secp]
import libp2p/crypto/curve25519
import ./peer_requests
import ./mix_node
import ./multiaddr as mix_multiaddr

export peer_requests

proc get*(ctx: BrokerContext, peerId: PeerId): Result[Opt[MixPubInfo], string] =
  ## Check keys and select an address supported by the wire format.
  let record = ?ReadMixPeer.request(ctx, peerId)
  if record.mixPubKey == default(Curve25519Key) or record.publicKey.scheme != Secp256k1:
    return ok(Opt.none(MixPubInfo))
  template candidate(address: MultiAddress) =
    if mix_multiaddr.multiAddrToBytes(peerId, address).isOk:
      return ok(
        Opt.some(
          MixPubInfo.init(peerId, address, record.mixPubKey, record.publicKey.skkey)
        )
      )

  for address in record.addresses:
    candidate(address)
  ok(Opt.none(MixPubInfo))

proc peerIds*(ctx: BrokerContext): Result[seq[PeerId], string] =
  ## Return each candidate ID once.
  var ids: seq[PeerId]
  var seen: HashSet[PeerId]
  for peerId in ?ListMixPeerIds.request(ctx):
    if not seen.containsOrIncl(peerId):
      ids.add(peerId)
  ok(ids)

proc add*(ctx: BrokerContext, info: MixPubInfo): Result[void, string] =
  ## Store one mix node through the registered provider.
  StoreMixPeer.request(ctx, info)

proc remove*(ctx: BrokerContext, peerId: PeerId): Result[bool, string] =
  ## Remove a mix node. Returns true when the node was present.
  RemoveMixPeer.request(ctx, peerId)

proc add*(ctx: BrokerContext, infos: seq[MixPubInfo]): Result[void, string] =
  ## Store each mix node in order and stop at the first error.
  for info in infos:
    ?ctx.add(info)
  ok()

proc count*(
    ctx: BrokerContext, exclude: openArray[PeerId]
): Result[int, string] {.gcsafe.} =
  ## Count usable peers after excluding the supplied IDs.
  var count = 0
  for peerId in ?ctx.peerIds():
    if peerId notin exclude and (?ctx.get(peerId)).isSome:
      count.inc()
  ok(count)

proc selectRandomNodes*(
    ctx: BrokerContext, rng: Rng, count: int, exclude: openArray[PeerId]
): Result[seq[MixPubInfo], string] {.gcsafe.} =
  ## Select distinct usable nodes at random, then randomize their order.
  if count < 0:
    return err("mix peer count must not be negative")
  if count == 0:
    return ok(newSeq[MixPubInfo]())
  var selected: seq[MixPubInfo]
  var seen = 0
  for peerId in ?ctx.peerIds():
    if peerId in exclude:
      continue
    (?ctx.get(peerId)).withValue(info):
      seen.inc()
      if selected.len < count:
        selected.add(info)
      else:
        let slot = rng.rand(0, seen - 1)
        if slot < count:
          selected[slot] = info
  if selected.len < count:
    return err("not enough usable mix nodes for a path")
  # Reservoir selection chooses a subset. Shuffle it for a random path order.
  for i in countdown(selected.high, 1):
    let j = rng.rand(0, i)
    swap(selected[i], selected[j])
  ok(selected)
