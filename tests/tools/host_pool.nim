# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## A test host pool. Like a host such as Delivery, it keeps a peer store, an
## address policy and exclusions, and answers MixProtocol through MixPool.

{.push raises: [].}

import std/[sets, sequtils, tables]
import results
import libp2p/[peerstore, peerid, multiaddress, wire, crypto/crypto]
import ./crypto
import libp2p_mix/[mix_pool, pool, mix_node]

export mix_pool, pool

type HostPool* = ref object of MixPool
  store*: PeerStore
  allowAllAddresses*: bool
  excluded: HashSet[PeerId]

proc new*(T: typedesc[HostPool], allowAllAddresses = false, store: PeerStore = nil): T =
  T(
    store: (if store.isNil: PeerStore.new() else: store),
    allowAllAddresses: allowAllAddresses,
    rng: rng(),
  )

proc accepts(pool: HostPool, address: MultiAddress): bool =
  if pool.allowAllAddresses:
    return true
  if not (TCP_IP4.match(address) or QUIC_V1_IP4.match(address)) or
      not isPublicMA(address):
    return false
  let transport = address[1].valueOr:
    return false
  let port = transport.protoArgument().valueOr:
    return false
  port.len == 2 and (port[0] != 0 or port[1] != 0)

method readPeer*(
    pool: HostPool, peerId: PeerId
): Result[MixPeerRecord, string] {.gcsafe, raises: [].} =
  if peerId in pool.excluded:
    return ok(MixPeerRecord())
  var record = MixPeerRecord(
    mixPubKey: pool.store[MixPubKeyBook][peerId], publicKey: pool.store[KeyBook][peerId]
  )
  for address in pool.store[AddressBook][peerId]:
    if pool.accepts(address):
      record.addresses.add(address)
  pool.store[LastSeenOutboundBook][peerId].withValue(address):
    if pool.accepts(address):
      record.addresses = @[address] & record.addresses.filterIt(it != address)
  ok(record)

method listPeerIds*(
    pool: HostPool
): Result[seq[PeerId], string] {.gcsafe, raises: [].} =
  ok(pool.store[MixPubKeyBook].book.keys.toSeq().filterIt(it notin pool.excluded))

proc addPeer*(pool: HostPool, info: MixPubInfo) =
  ## Store a peer and lift its exclusion.
  pool.store[MixPubKeyBook][info.peerId] = info.mixPubKey
  let addresses = pool.store[AddressBook][info.peerId]
  if info.multiAddr notin addresses:
    pool.store[AddressBook].set(
      info.peerId, addresses & @[info.multiAddr], AddressConfidence.Infinite
    )
  if pool.store[KeyBook][info.peerId].scheme != Secp256k1:
    pool.store[KeyBook][info.peerId] =
      PublicKey(scheme: Secp256k1, skkey: info.libp2pPubKey)
  pool.excluded.excl(info.peerId)

proc removePeer*(pool: HostPool, peerId: PeerId): bool =
  pool.excluded.excl(peerId)
  pool.store[MixPubKeyBook].del(peerId)

proc updatePeer*(pool: HostPool, info: MixPubInfo) =
  ## Replace the peer keys and addresses with the latest discovery result.
  pool.store[MixPubKeyBook][info.peerId] = info.mixPubKey
  pool.store[KeyBook][info.peerId] =
    PublicKey(scheme: Secp256k1, skkey: info.libp2pPubKey)
  pool.store[AddressBook].set(
    info.peerId, @[info.multiAddr], AddressConfidence.Infinite
  )

proc exclude*(pool: HostPool, peerId: PeerId) =
  pool.excluded.incl(peerId)

proc restore*(pool: HostPool, peerId: PeerId) =
  pool.excluded.excl(peerId)

# Helpers for tests that run with either pool class.

proc addPeer*(pool: MixPool, info: MixPubInfo) =
  if pool of HostPool:
    HostPool(pool).addPeer(info)
  elif pool of MixNodePool:
    MixNodePool(pool).add(info)
  else:
    raiseAssert "unknown pool class"

proc addPeers*(pool: MixPool, infos: openArray[MixPubInfo]) =
  for info in infos:
    pool.addPeer(info)

proc removePeer*(pool: MixPool, peerId: PeerId): bool =
  if pool of HostPool:
    HostPool(pool).removePeer(peerId)
  elif pool of MixNodePool:
    MixNodePool(pool).remove(peerId)
  else:
    raiseAssert "unknown pool class"

proc newHostPool*(): HostPool =
  ## A host pool that accepts every address.
  HostPool.new(allowAllAddresses = true)

proc newStockPool*(store: PeerStore = nil): MixNodePool =
  MixNodePool.new((if store.isNil: PeerStore.new() else: store), rng())
