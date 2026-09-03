# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Mix Node Pool Management
##
## This module provides an abstraction layer for managing mix node information.
## It encapsulates access to the peerStore's MixPubKeyBook, AddressBook, and KeyBook,
## providing a clean interface for the mix protocol to interact with mix node data.

import std/[sequtils, tables]
import results
import chronos/timer
import libp2p/peerstore
import libp2p/peerid
import libp2p/multiaddress
import libp2p/crypto/crypto
import libp2p/crypto/curve25519
import ./mix_node
import ./multiaddr as mix_multiaddr

export mix_node.MixPubInfo

type MixPubKeyBook* = ref object of PeerBook[Curve25519Key]
  ## Tracks Curve25519 mix public keys per peer. Defined here so the mix
  ## package owns its peer-store extension and libp2p core stays free of
  ## mix-specific types.

func isSupportedMultiaddr(maddr: MultiAddress): bool =
  ## Returns true if the multiaddress is supported by the mix protocol.
  ## Mix protocol supports IPv4 addresses with TCP or QUIC-v1 transports,
  ## including circuit-relay addresses that use these transports.
  let baseAddr = mix_multiaddr.getBaseTransport(maddr).valueOr:
    return false
  TCP_IP4.match(baseAddr) or QUIC_V1_IP4.match(baseAddr)

func findSupportedMultiaddr(maddrs: seq[MultiAddress]): Opt[MultiAddress] =
  ## Returns the first multiaddress that is supported by the mix protocol.
  for maddr in maddrs:
    if isSupportedMultiaddr(maddr):
      return Opt.some(maddr)
  Opt.none(MultiAddress)

type MixNodePool* = ref object
  ## Manages mix node public information through the peerStore.
  ## This abstraction allows the mix protocol to interact with mix node data
  ## without directly coupling to peerStore implementation details.
  ##
  ## Future enhancements:
  ## - Peer scoring: Track node reliability, latency, and performance metrics
  ## - Pool maintenance: Automatic pruning of stale/unresponsive nodes
  peerStore: PeerStore

proc new*(T: typedesc[MixNodePool], peerStore: PeerStore): T =
  ## Create a new MixNodePool instance backed by the given peerStore.
  T(peerStore: peerStore)

proc add*(pool: MixNodePool, info: MixPubInfo) =
  ## Add a mix node to the pool.
  ## MixPubKeyBook entry is always updated.
  ## Address is added to AddressBook if not already present.
  ## KeyBook is only set if not already present (to avoid overwriting
  ## keys set by the Identify protocol).
  pool.peerStore[MixPubKeyBook][info.peerId] = info.mixPubKey

  # Add address if not already present.
  # Infinite confidence prevents the libp2p v2.0.0 1h auto-prune from
  # evicting mix node addresses we curated from discovery/static config.
  let existingAddrs = pool.peerStore[AddressBook][info.peerId]
  if info.multiAddr notin existingAddrs:
    pool.peerStore[AddressBook].set(
      info.peerId, existingAddrs & @[info.multiAddr], AddressConfidence.Infinite
    )

  # Only set key if peer has no key yet
  let existingKey = pool.peerStore[KeyBook][info.peerId]
  if existingKey.scheme != Secp256k1:
    pool.peerStore[KeyBook][info.peerId] =
      PublicKey(scheme: Secp256k1, skkey: info.libp2pPubKey)

proc add*(pool: MixNodePool, infos: seq[MixPubInfo]) =
  ## Add multiple mix nodes to the pool.
  for info in infos:
    pool.add(info)

proc remove*(pool: MixNodePool, peerId: PeerId): bool =
  ## Remove a mix node from the pool. Returns true if the node was present.
  pool.peerStore[MixPubKeyBook].del(peerId)
  # Note: We only delete from MixPubKeyBook. The peer may still have
  # entries in AddressBook/KeyBook for other protocols.

proc newestSupportedMultiaddr*(
    entries: seq[AddressEntry],
    live: seq[MultiAddress],
    preferred = Opt.none(MultiAddress),
): Opt[MultiAddress] =
  ## The supported address with the latest `lastUpdated` among the entries
  ## whose address is in `live` (the book's non-expired addresses). On a tie
  ## `preferred` wins when it is one of them (the last outbound address), else
  ## the first entry in book order.
  var best = Opt.none(AddressEntry)
  for entry in entries:
    if entry.address notin live or not isSupportedMultiaddr(entry.address):
      continue
    if best.isNone() or entry.lastUpdated > best.get().lastUpdated or (
      entry.lastUpdated == best.get().lastUpdated and
      preferred == Opt.some(entry.address)
    ):
      best = Opt.some(entry)
  if best.isNone():
    return Opt.none(MultiAddress)
  Opt.some(best.get().address)

proc get*(pool: MixNodePool, peerId: PeerId): Opt[MixPubInfo] =
  ## Get MixPubInfo for a peer. Returns none if peer is not in the pool
  ## or if required information (address, key) is missing.
  let mixPubKey = pool.peerStore[MixPubKeyBook][peerId]
  if mixPubKey == default(Curve25519Key):
    return Opt.none(MixPubInfo)

  # Get the address: the most recently updated supported live entry of the
  # AddressBook; the last outbound address wins a tie. A configured address
  # has Infinite confidence and never expires, so without the recency rule a
  # node that moved to a new port stays unreachable until restart, although
  # discovery delivered the new address. An expired last outbound address is
  # not in the live list and loses.
  # Mix protocol only supports IPv4 addresses with TCP or QUIC-v1 transports
  let supportedAddr = newestSupportedMultiaddr(
    pool.peerStore[AddressBook].entries(peerId),
    pool.peerStore[AddressBook][peerId],
    pool.peerStore[LastSeenOutboundBook][peerId],
  ).valueOr:
    return Opt.none(MixPubInfo)

  let pubKey = pool.peerStore[KeyBook][peerId]
  if pubKey.scheme != Secp256k1:
    return Opt.none(MixPubInfo)

  Opt.some(MixPubInfo.init(peerId, supportedAddr, mixPubKey, pubKey.skkey))

proc peerIds*(pool: MixNodePool): seq[PeerId] =
  ## Get all peer IDs in the mix node pool.
  pool.peerStore[MixPubKeyBook].book.keys.toSeq()

proc len*(pool: MixNodePool): int =
  ## Get the number of mix nodes in the pool.
  pool.peerStore[MixPubKeyBook].len
