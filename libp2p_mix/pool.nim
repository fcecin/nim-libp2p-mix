# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[sequtils, tables]
import chronos, results
import libp2p/[peerstore, peerid, multiaddress, peeraddrpolicy, wire]
import libp2p/crypto/[crypto, curve25519, secp]
import ./mix_node
import ./multiaddr as mix_multiaddr

export mix_node.MixPubInfo, peeraddrpolicy

const publicDirectAddressPolicy* = proc(ma: MultiAddress): bool {.gcsafe, raises: [].} =
  ma.isPublicMA() and not ma.isCircuitRelayMA()

type
  MixPubKeyBook* = ref object of PeerBook[Curve25519Key]

  MixNodeSource* {.pure.} = enum
    Discovered
    Configured

  MixPoolConfig* = object
    addressPolicy*: PeerAddressPolicy = publicDirectAddressPolicy
    discoveredTtl*: Duration = 1.hours
    failureBackoff*: Duration = 30.minutes
    maintenanceInterval*: Duration = 15.seconds
    maxDiscovered*: int = 1000

  MixPoolEventKind* {.pure.} = enum
    Owned
    Updated
    EligibilityChanged
    Removed
    DialSucceeded
    DialFailed
    DialIgnored

  MixPoolEvent* = object
    kind*: MixPoolEventKind
    peerId*: PeerId
    source*: MixNodeSource
    known*: bool
    eligible*: bool

  MixPoolHandler* = proc(event: MixPoolEvent) {.gcsafe, raises: [].}
  MixConnectionCheck* = proc(peerId: PeerId): bool {.gcsafe, raises: [].}

  MixPoolCounters* = object
    owned*, removed*, dialSucceeded*, dialFailed*, dialIgnored*: uint64

  MixDialOutcome* {.pure.} = enum
    Succeeded
    Failed
    Cancelled

  KnownMixNode = object
    source: MixNodeSource
    mixPubKey: Curve25519Key
    libp2pPubKey: SkPublicKey
    stored, configured: seq[MultiAddress]
    lastDialed: Opt[MultiAddress]
    lastSeen: Moment
    failedAt: Opt[Moment]

  BookUpdate = enum
    MixKeyUpdate
    AddressUpdate
    KeyUpdate
    OutboundUpdate

  BookObserver = proc(peerId: PeerId, update: BookUpdate) {.gcsafe, raises: [].}
  MixObserverBook = ref object of PeerBook[bool]
    installed: bool
    nextId: uint64
    observers: Table[uint64, BookObserver]

  MixNodePool* = ref object
    peerStore: PeerStore
    selfId: PeerId
    config*: MixPoolConfig
    known: Table[PeerId, KnownMixNode]
    eligible: Table[PeerId, MixPubInfo]
    handlers: Table[uint64, MixPoolHandler]
    nextHandler: uint64
    observerId: uint64
    connected: MixConnectionCheck
    loop: Future[void]
    stopped*: bool
    counters*: MixPoolCounters

proc accepts*(pool: MixNodePool, peerId: PeerId, address: MultiAddress): bool =
  let base = mix_multiaddr.getBaseTransport(address).valueOr:
    return false
  let policy = pool.config.addressPolicy
  isDialableMA(address) and isDialableMA(base) and policy.accepts(address) and
    policy.accepts(base) and mix_multiaddr.multiAddrToBytes(peerId, address).isOk()

proc hopAddresses*(pool: MixNodePool, peerId: PeerId): seq[MultiAddress] =
  var candidates: seq[MultiAddress]
  pool.known.withValue(peerId, node):
    node.lastDialed.withValue(address):
      candidates.add(address)
    candidates.add(node.stored)
    candidates.add(node.configured)
  for address in candidates:
    if address notin result and pool.accepts(peerId, address):
      result.add(address)

proc get*(pool: MixNodePool, peerId: PeerId): Opt[MixPubInfo] =
  pool.known.withValue(peerId, node):
    if node.failedAt.isSome and
        Moment.now() - node.failedAt.get() < pool.config.failureBackoff:
      return Opt.none(MixPubInfo)
    let addresses = pool.hopAddresses(peerId)
    if addresses.len > 0:
      return Opt.some(
        MixPubInfo.init(peerId, addresses[0], node.mixPubKey, node.libp2pPubKey)
      )
  Opt.none(MixPubInfo)

proc peerIds*(pool: MixNodePool): seq[PeerId] =
  for peerId in pool.known.keys:
    if pool.get(peerId).isSome:
      result.add(peerId)

proc len*(pool: MixNodePool): int =
  pool.peerIds().len

proc knownPeerIds*(pool: MixNodePool): seq[PeerId] =
  pool.known.keys.toSeq()

proc contains*(pool: MixNodePool, peerId: PeerId): bool =
  peerId in pool.known

proc source*(pool: MixNodePool, peerId: PeerId): Opt[MixNodeSource] =
  pool.known.withValue(peerId, node):
    return Opt.some(node.source)
  Opt.none(MixNodeSource)

proc notify(
    pool: MixNodePool,
    peerId: PeerId,
    kind: MixPoolEventKind,
    source = MixNodeSource.Discovered,
) =
  let event = MixPoolEvent(
    kind: kind,
    peerId: peerId,
    source: pool.source(peerId).get(source),
    known: peerId in pool.known,
    eligible: pool.get(peerId).isSome,
  )
  let handlers = pool.handlers.values.toSeq()
  for handler in handlers:
    handler(event)

proc addChangeHandler*(pool: MixNodePool, handler: MixPoolHandler): uint64 =
  pool.nextHandler.inc()
  pool.handlers[pool.nextHandler] = handler
  pool.nextHandler

proc removeChangeHandler*(pool: MixNodePool, id: uint64) =
  pool.handlers.del(id)

proc refresh(pool: MixNodePool, peerId: PeerId) =
  let current = pool.get(peerId)
  let previous = pool.eligible.getOrDefault(peerId)
  let wasEligible = peerId in pool.eligible
  if current.isSome:
    pool.eligible[peerId] = current.get()
  else:
    pool.eligible.del(peerId)
  if wasEligible != current.isSome:
    pool.notify(peerId, MixPoolEventKind.EligibilityChanged)
  elif current.isSome and previous != current.get():
    pool.notify(peerId, MixPoolEventKind.Updated)

proc remove*(pool: MixNodePool, peerId: PeerId): bool =
  let source = pool.source(peerId).valueOr:
    return false
  pool.known.del(peerId)
  pool.eligible.del(peerId)
  pool.counters.removed.inc()
  pool.notify(peerId, MixPoolEventKind.Removed, source)
  true

proc evictAtLimit(pool: MixNodePool) =
  var count = 0
  var victim: Opt[PeerId]
  var rank: (bool, Moment)
  for peerId, node in pool.known:
    if node.source == MixNodeSource.Configured:
      continue
    count.inc()
    let candidate = (pool.get(peerId).isSome, node.lastSeen)
    if victim.isNone or candidate < rank:
      victim = Opt.some(peerId)
      rank = candidate
  if count >= pool.config.maxDiscovered and victim.isSome:
    discard pool.remove(victim.get())

proc ingest*(
    pool: MixNodePool,
    info: MixPubInfo,
    source = MixNodeSource.Discovered,
    now = Moment.now(),
) =
  ## A discovery record with a mix key refreshes the lifetime of its node.
  if info.peerId == pool.selfId or info.mixPubKey == default(Curve25519Key):
    return
  let joined = info.peerId notin pool.known
  if joined and source == MixNodeSource.Discovered:
    if pool.config.maxDiscovered <= 0:
      return
    pool.evictAtLimit()
  var node = pool.known.getOrDefault(info.peerId)
  if joined or source == MixNodeSource.Configured:
    node.source = source
  if source == MixNodeSource.Configured:
    if info.multiAddr notin node.configured:
      node.configured.add(info.multiAddr)
    node.failedAt = Opt.none(Moment)
  else:
    node.stored = @[info.multiAddr]
  node.mixPubKey = info.mixPubKey
  node.libp2pPubKey = info.libp2pPubKey
  node.lastSeen = now
  pool.known[info.peerId] = node
  if joined:
    pool.counters.owned.inc()
  pool.notify(
    info.peerId, if joined: MixPoolEventKind.Owned else: MixPoolEventKind.Updated
  )
  pool.refresh(info.peerId)

proc add*(pool: MixNodePool, info: MixPubInfo) =
  ## Configured nodes do not expire. The peer store receives a copy.
  pool.ingest(info, MixNodeSource.Configured)
  if info.peerId notin pool.known:
    return
  let store = pool.peerStore
  let addresses = store[AddressBook][info.peerId]
  if info.multiAddr notin addresses:
    store[AddressBook].set(
      info.peerId, addresses & @[info.multiAddr], AddressConfidence.Infinite
    )
  store[KeyBook][info.peerId] = PublicKey(scheme: Secp256k1, skkey: info.libp2pPubKey)
  store[MixPubKeyBook][info.peerId] = info.mixPubKey

proc add*(pool: MixNodePool, infos: seq[MixPubInfo]) =
  for info in infos:
    pool.add(info)

proc observe(pool: MixNodePool, peerId: PeerId, update: BookUpdate, fresh = true) =
  if pool.stopped or peerId == pool.selfId:
    return
  let store = pool.peerStore
  let mixKey = store[MixPubKeyBook][peerId]
  let joined = peerId notin pool.known
  if joined:
    if mixKey == default(Curve25519Key) or pool.config.maxDiscovered <= 0:
      return
    var key = store[KeyBook][peerId]
    if key.scheme != Secp256k1:
      if not peerId.extractPublicKey(key) or key.scheme != Secp256k1:
        return
    pool.evictAtLimit()
    pool.known[peerId] = KnownMixNode(
      source: MixNodeSource.Discovered,
      libp2pPubKey: key.skkey,
      mixPubKey: mixKey,
      lastSeen: Moment.now(),
    )
    pool.counters.owned.inc()
  pool.known.withValue(peerId, node):
    if mixKey != default(Curve25519Key):
      node.mixPubKey = mixKey
      if fresh and update == MixKeyUpdate:
        node.lastSeen = Moment.now()
    let addresses = store[AddressBook][peerId]
    if addresses.len > 0:
      node.stored = addresses
    let key = store[KeyBook][peerId]
    if key.scheme == Secp256k1:
      node.libp2pPubKey = key.skkey
    if joined or update == OutboundUpdate:
      let address = store[LastSeenOutboundBook][peerId]
      if address.isSome:
        node.lastDialed = address
        if fresh:
          node.lastSeen = Moment.now()
  pool.notify(peerId, if joined: MixPoolEventKind.Owned else: MixPoolEventKind.Updated)
  pool.refresh(peerId)

proc dispatch(hub: MixObserverBook, peerId: PeerId, update: BookUpdate) =
  let observers = hub.observers.values.toSeq()
  for observer in observers:
    observer(peerId, update)

proc attach(pool: MixNodePool) =
  if pool.observerId != 0:
    return
  let store = pool.peerStore
  let hub = store[MixObserverBook]
  if not hub.installed:
    # Create each book before a peer store deletion can call a handler.
    let mixKeys = store[MixPubKeyBook]
    let addresses = store[AddressBook]
    let keys = store[KeyBook]
    let outbound = store[LastSeenOutboundBook]
    mixKeys.addHandler(
      proc(peerId: PeerId) =
        hub.dispatch(peerId, MixKeyUpdate)
    )
    addresses.addHandler(
      proc(peerId: PeerId) =
        hub.dispatch(peerId, AddressUpdate)
    )
    keys.addHandler(
      proc(peerId: PeerId) =
        hub.dispatch(peerId, KeyUpdate)
    )
    outbound.addHandler(
      proc(peerId: PeerId) =
        hub.dispatch(peerId, OutboundUpdate)
    )
    hub.installed = true
  hub.nextId.inc()
  pool.observerId = hub.nextId
  hub.observers[pool.observerId] = proc(peerId: PeerId, update: BookUpdate) =
    pool.observe(peerId, update)
  for peerId in store[MixPubKeyBook].book.keys.toSeq():
    pool.observe(peerId, MixKeyUpdate, fresh = false)

proc reportDial*(
    pool: MixNodePool,
    peerId: PeerId,
    addresses: seq[MultiAddress],
    outcome: MixDialOutcome,
    hadConnection: bool,
    hasOtherConnection: bool,
    connectionLimit = false,
    now = Moment.now(),
) =
  ## External dial evidence must use the same addresses as the mix hop.
  if pool.stopped or peerId notin pool.known:
    return
  let hops = pool.hopAddresses(peerId)
  if addresses.len == 0 or not addresses.allIt(it in hops):
    return
  if outcome == MixDialOutcome.Succeeded:
    pool.known.withValue(peerId, node):
      node.lastSeen = now
      node.failedAt = Opt.none(Moment)
    pool.counters.dialSucceeded.inc()
    pool.notify(peerId, MixPoolEventKind.DialSucceeded)
  elif hadConnection or not hasOtherConnection or connectionLimit:
    pool.counters.dialIgnored.inc()
    pool.notify(peerId, MixPoolEventKind.DialIgnored)
    return
  else:
    pool.known.withValue(peerId, node):
      node.lastDialed = Opt.none(MultiAddress)
      if node.source == MixNodeSource.Discovered:
        node.failedAt = Opt.some(now)
    pool.counters.dialFailed.inc()
    pool.notify(peerId, MixPoolEventKind.DialFailed)
  pool.refresh(peerId)

proc maintain*(pool: MixNodePool, now = Moment.now()) =
  for peerId in pool.known.keys.toSeq():
    var expired = false
    pool.known.withValue(peerId, node):
      if not pool.connected.isNil and pool.connected(peerId):
        node.lastSeen = now
      elif node.source == MixNodeSource.Discovered:
        expired = now - node.lastSeen >= pool.config.discoveredTtl
      if node.failedAt.isSome and now - node.failedAt.get() >= pool.config.failureBackoff:
        node.failedAt = Opt.none(Moment)
    if expired:
      discard pool.remove(peerId)
    else:
      pool.refresh(peerId)

proc maintenanceLoop(pool: MixNodePool) {.async: (raises: [CancelledError]).} =
  while true:
    pool.maintain()
    await sleepAsync(pool.config.maintenanceInterval)

proc start*(pool: MixNodePool) =
  pool.stopped = false
  pool.attach()
  if pool.loop.isNil or pool.loop.finished:
    pool.loop = pool.maintenanceLoop()

proc stop*(pool: MixNodePool) {.async: (raises: []).} =
  pool.stopped = true
  if pool.observerId != 0:
    pool.peerStore[MixObserverBook].observers.del(pool.observerId)
    pool.observerId = 0
  if not pool.loop.isNil:
    await pool.loop.cancelAndWait()
    pool.loop = nil

proc new*(
    T: typedesc[MixNodePool],
    peerStore: PeerStore,
    selfId = PeerId(),
    config = MixPoolConfig(),
    connected: MixConnectionCheck = nil,
): T =
  doAssert config.maintenanceInterval > ZeroDuration
  result = T(peerStore: peerStore, selfId: selfId, config: config, connected: connected)
  result.attach()
