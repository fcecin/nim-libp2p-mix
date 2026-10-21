# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Standalone providers backed by `MixNodePool`.

{.push raises: [].}

import std/sequtils
import chronos, results
import libp2p/[peerstore, peerid, crypto/crypto]
import ./pool
import ./peer_selection

export peer_selection

proc registerRandomReplySelection*(ctx: BrokerContext, rng: Rng): Result[void, string] =
  ## Register a reply selector that picks one usable peer at random.
  ?SelectReplyPeer.setProvider(
    ctx,
    proc(excluded: seq[PeerId]): Future[Result[PeerId, string]] {.async.} =
      let peers = ctx.selectRandomNodes(rng, 1, excluded).valueOr:
        return err(error)
      return ok(peers[0].peerId),
  )

  ok()

proc registerMixPeerProviders*(
    ctx: BrokerContext, store: PeerStore
): Result[void, string] =
  ## Register the storage providers. The caller clears them with `clearMixProviders`.
  let pool = MixNodePool.new(store)
  var registered = false
  ?ReadMixPeer.setProvider(
    ctx,
    proc(peerId: PeerId): Result[MixPeerRecord, string] =
      var addresses = store[AddressBook][peerId]
      store[LastSeenOutboundBook][peerId].withValue(address):
        addresses = @[address] & addresses.filterIt(it != address)
      ok(
        MixPeerRecord(
          mixPubKey: store[MixPubKeyBook][peerId],
          publicKey: store[KeyBook][peerId],
          addresses: addresses,
        )
      ),
  )
  defer:
    if not registered:
      ReadMixPeer.clearProvider(ctx)
  ?StoreMixPeer.setProvider(
    ctx,
    proc(info: MixPubInfo): Result[void, string] =
      pool.add(info)
      ok(),
  )
  defer:
    if not registered:
      StoreMixPeer.clearProvider(ctx)
  ?RemoveMixPeer.setProvider(
    ctx,
    proc(peerId: PeerId): Result[bool, string] =
      ok(pool.remove(peerId)),
  )
  defer:
    if not registered:
      RemoveMixPeer.clearProvider(ctx)
  ?ListMixPeerIds.setProvider(
    ctx,
    proc(): Result[seq[PeerId], string] =
      ok(pool.peerIds()),
  )
  registered = true
  ok()
