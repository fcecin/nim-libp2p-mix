# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Mix Node Pool Management
##
## This module provides an abstraction layer for managing mix node information.
## It keeps a record of each node added through `add`, and it reads the
## peerStore's MixPubKeyBook, AddressBook, and KeyBook for every other node.
## For each node it reads the address from the LastSeenOutboundBook and the
## AddressBook.

import std/[sequtils, tables]
import results
import libp2p/peerstore
import libp2p/peerid
import libp2p/multiaddress
import libp2p/peeraddrpolicy
import libp2p/wire
import libp2p/crypto/crypto
import libp2p/crypto/curve25519
import ./mix_node
import ./multiaddr as mix_multiaddr

export mix_node.MixPubInfo

const publicDirectAddressPolicy* = proc(ma: MultiAddress): bool {.gcsafe, raises: [].} =
  ## Accepts a public address that is not a circuit-relay address.
  isPublicMA(ma) and not isCircuitRelayMA(ma)

type MixPubKeyBook* = ref object of PeerBook[Curve25519Key]
  ## Tracks Curve25519 mix public keys per peer. Defined here so the mix
  ## package owns its peer-store extension and libp2p core stays free of
  ## mix-specific types.

func isSupportedMultiaddr*(maddr: MultiAddress): bool =
  ## Returns true if the multiaddress is supported by the mix protocol.
  ## Mix protocol supports IPv4 addresses with TCP or QUIC-v1 transports,
  ## including circuit-relay addresses that use these transports.
  let baseAddr = mix_multiaddr.getBaseTransport(maddr).valueOr:
    return false
  TCP_IP4.match(baseAddr) or QUIC_V1_IP4.match(baseAddr)

type MixNodePool* = ref object of RootObj
  ## Manages mix node public information through its own record of added
  ## nodes and the peerStore.
  ## This abstraction allows the mix protocol to interact with mix node data
  ## without directly coupling to peerStore implementation details.
  ## An application can make a subclass that overrides `add`, `remove`, `get`,
  ## `peerIds`, `len` and `accepts`. A subclass that does not get a peer store
  ## from `new` overrides `add`, `remove`, `get` and `peerIds`, because these
  ## base methods use the peer store. With a nil policy, the base `accepts`
  ## returns true for each address that the mix protocol supports.
  ##
  ## Future enhancements:
  ## - Peer scoring: Track node reliability, latency, and performance metrics
  ## - Pool maintenance: Automatic pruning of stale/unresponsive nodes
  peerStore: PeerStore
  addressPolicy: PeerAddressPolicy
    ## Decides which hop addresses the pool uses. The default accepts every address.
    ## The base `peerIds` and `len` still count a node that the policy refuses.
    ## A send that draws it for a forward path removes it from the pool. A reply
    ## path or a cover packet that draws it fails, and the node stays in the pool.
  added: Table[PeerId, MixPubInfo]
    ## The nodes added through `add`. `get` reads them from this table first.

proc new*(
    T: typedesc[MixNodePool],
    peerStore: PeerStore,
    addressPolicy: PeerAddressPolicy = defaultAddressPolicy,
): T =
  ## Create a new MixNodePool instance backed by the given peerStore.
  T(peerStore: peerStore, addressPolicy: addressPolicy)

method accepts*(
    pool: MixNodePool, maddr: MultiAddress
): bool {.base, gcsafe, raises: [].} =
  ## Returns true if the mix protocol supports the multiaddress and the
  ## address policy of the pool accepts it. With a nil policy it checks only
  ## the mix protocol. libp2p `accepts` has no nil check before 2.4.0, so this
  ## method calls the policy itself. A subclass with its own policy overrides it.
  isSupportedMultiaddr(maddr) and
    (pool.addressPolicy.isNil() or pool.addressPolicy(maddr))

proc firstAcceptedMultiaddr(
    pool: MixNodePool, maddrs: seq[MultiAddress]
): Opt[MultiAddress] =
  ## Returns the first multiaddress that the pool accepts.
  for maddr in maddrs:
    if pool.accepts(maddr):
      return Opt.some(maddr)
  Opt.none(MultiAddress)

method add*(pool: MixNodePool, info: MixPubInfo) {.base, gcsafe, raises: [].} =
  ## Add a mix node to the pool.
  ## The pool keeps its own record of the node until `remove`. `get` reads the
  ## keys of the node from this record, also when other code writes to the books.
  ## MixPubKeyBook entry is always updated.
  ## Address is added to AddressBook if not already present.
  ## KeyBook is only set if not already present (to avoid overwriting
  ## keys set by the Identify protocol).
  pool.added[info.peerId] = info
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

method remove*(pool: MixNodePool, peerId: PeerId): bool {.base, gcsafe, raises: [].} =
  ## Remove a mix node from the pool. Returns true if the node was present.
  let wasAdded = pool.added.hasKey(peerId)
  pool.added.del(peerId)
  # Preserve AddressBook/KeyBook entries used by other protocols.
  let wasInBook = pool.peerStore[MixPubKeyBook].del(peerId)
  wasAdded or wasInBook

method get*(
    pool: MixNodePool, peerId: PeerId
): Opt[MixPubInfo] {.base, gcsafe, raises: [].} =
  ## Get MixPubInfo for a peer. Returns none if peer is not in the pool
  ## or if required information (address, key) is missing.
  ## For a node added through `add`, `get` reads the keys from the pool's own
  ## record. The address is the first one that the pool accepts, out of the
  ## last outbound address, then the address book, then the added address.
  pool.added.withValue(peerId, info):
    let lastSeenAddr = pool.peerStore[LastSeenOutboundBook][peerId]
    if lastSeenAddr.isSome and pool.accepts(lastSeenAddr.get):
      return Opt.some(
        MixPubInfo.init(peerId, lastSeenAddr.get, info.mixPubKey, info.libp2pPubKey)
      )
    let addresses = pool.peerStore[AddressBook][peerId] & @[info.multiAddr]
    let supportedAddr = pool.firstAcceptedMultiaddr(addresses).valueOr:
      return Opt.none(MixPubInfo)
    return Opt.some(
      MixPubInfo.init(peerId, supportedAddr, info.mixPubKey, info.libp2pPubKey)
    )

  let mixPubKey = pool.peerStore[MixPubKeyBook][peerId]
  if mixPubKey == default(Curve25519Key):
    return Opt.none(MixPubInfo)

  # Get the address - prefer LastSeenOutboundBook, fall back to AddressBook
  # The address is the first one that the pool accepts
  var supportedAddr: MultiAddress
  let lastSeenAddr = pool.peerStore[LastSeenOutboundBook][peerId]
  if lastSeenAddr.isSome and pool.accepts(lastSeenAddr.get):
    supportedAddr = lastSeenAddr.get
  else:
    supportedAddr = pool.firstAcceptedMultiaddr(pool.peerStore[AddressBook][peerId]).valueOr:
      return Opt.none(MixPubInfo)

  let pubKey = pool.peerStore[KeyBook][peerId]
  if pubKey.scheme != Secp256k1:
    return Opt.none(MixPubInfo)

  Opt.some(MixPubInfo.init(peerId, supportedAddr, mixPubKey, pubKey.skkey))

method peerIds*(pool: MixNodePool): seq[PeerId] {.base, gcsafe, raises: [].} =
  ## Get all peer IDs in the mix node pool.
  ## A subclass returns the nodes that a path can use now.
  pool.added.keys.toSeq() &
    pool.peerStore[MixPubKeyBook].book.keys.toSeq().filterIt(it notin pool.added)

method len*(pool: MixNodePool): int {.base, gcsafe, raises: [].} =
  ## Get the number of mix nodes in the pool.
  ## A subclass that overrides `len` returns the number of nodes in `peerIds`.
  pool.peerIds().len
