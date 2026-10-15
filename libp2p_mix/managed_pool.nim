# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Managed Mix Node Pool
##
## An optional pool that keeps its own table of mix nodes. It reads no peer
## store book. Each node has a source. A configured node stays until
## `remove`. A discovered node leaves when its record is older than
## `discoveredTtl`, or when the pool holds `maxDiscovered` discovered nodes
## and a newer one joins. A suspended node stays in the pool and leaves mix
## paths until its suspension ends. A change handler sees each node that
## joins or leaves.
##
## A hop address is the first address of the record that the pool accepts.
## The pool reads no `LastSeenOutboundBook`, so an application that prefers
## the last outbound address gives that address to a discovered `add`. At
## `maxDiscovered` the pool can evict a suspended node, because a path cannot
## use it. A later `add` of that node starts with no suspension.
##
## The protocol reads the pool through `MixNodePool`. An application sets
## `mixProto.nodePool` to a managed pool after it creates the protocol, and
## it calls `start` and `stop` for the maintenance loop. `MixProtocol.start`
## and `stop` do not start or stop it.

{.push raises: [].}

import std/[sequtils, tables]
import chronos, results
import libp2p/[peerid, multiaddress, peeraddrpolicy]
import libp2p/crypto/[curve25519, secp]
import ./mix_node
import ./pool

export pool

type
  MixNodeSource* {.pure.} = enum
    Discovered
    Configured

  MixConnectionCheck* = proc(peerId: PeerId): bool {.gcsafe, raises: [].}
    ## Tells whether this node has a connection to a peer.

  ManagedPoolConfig* = object
    addressPolicy*: PeerAddressPolicy = defaultAddressPolicy
    discoveredTtl*: Duration = 1.hours
    maxDiscovered*: int = 1000
    maintenanceInterval*: Duration = 15.seconds
    isConnected*: MixConnectionCheck
      ## When set, `maintain` keeps a discovered node with a connection. A nil
      ## check keeps no node.

  ManagedPoolChangeHandler* = proc(peerId: PeerId, present: bool) {.gcsafe, raises: [].}
    ## Called with `present` true when a node joins the pool and false when it
    ## leaves.

  ManagedNode = object
    source: MixNodeSource
    addresses: seq[MultiAddress]
    mixPubKey: Curve25519Key
    libp2pPubKey: SkPublicKey
    lastSeen: Moment
    suspendedUntil: Opt[Moment]

  ManagedMixNodePool* = ref object of MixNodePool
    config: ManagedPoolConfig
    selfId: PeerId
    nodes: Table[PeerId, ManagedNode]
    handlers: Table[uint64, ManagedPoolChangeHandler]
    lastHandlerId: uint64
    maintenanceLoop: Future[void]

proc new*(
    T: typedesc[ManagedMixNodePool], config = ManagedPoolConfig(), selfId = PeerId()
): T =
  ## Create a managed pool. The pool never holds `selfId`.
  doAssert config.maintenanceInterval > ZeroDuration,
    "maintenanceInterval must be positive"
  doAssert config.maxDiscovered >= 0, "maxDiscovered must not be negative"
  T(config: config, selfId: selfId)

func config*(pool: ManagedMixNodePool): ManagedPoolConfig =
  pool.config

method accepts*(
    pool: ManagedMixNodePool, maddr: MultiAddress
): bool {.gcsafe, raises: [].} =
  ## Returns true if the mix protocol supports the multiaddress and the
  ## address policy of the pool accepts it. A nil policy accepts each address.
  isSupportedMultiaddr(maddr) and
    (pool.config.addressPolicy.isNil() or pool.config.addressPolicy(maddr))

proc notify(pool: ManagedMixNodePool, peerId: PeerId, present: bool) =
  let handlers = pool.handlers.values.toSeq()
  for handler in handlers:
    handler(peerId, present)

proc addChangeHandler*(
    pool: ManagedMixNodePool, handler: ManagedPoolChangeHandler
): uint64 =
  ## Register a handler. Returns the id for `removeChangeHandler`.
  pool.lastHandlerId.inc()
  pool.handlers[pool.lastHandlerId] = handler
  pool.lastHandlerId

proc removeChangeHandler*(pool: ManagedMixNodePool, id: uint64) =
  pool.handlers.del(id)

func contains*(pool: ManagedMixNodePool, peerId: PeerId): bool =
  ## Returns true when the pool has a record of the node, suspended or not.
  peerId in pool.nodes

func allPeerIds*(pool: ManagedMixNodePool): seq[PeerId] =
  ## Returns every node in the pool, suspended or not. `peerIds` returns the
  ## nodes that a path can use now.
  pool.nodes.keys.toSeq()

func source*(pool: ManagedMixNodePool, peerId: PeerId): Opt[MixNodeSource] =
  pool.nodes.withValue(peerId, node):
    return Opt.some(node.source)
  Opt.none(MixNodeSource)

func suspendedUntil*(pool: ManagedMixNodePool, peerId: PeerId): Opt[Moment] =
  ## The end of the suspension of the node, or none. A time that has passed
  ## stays until the next `maintain`.
  pool.nodes.withValue(peerId, node):
    return node.suspendedUntil
  Opt.none(Moment)

proc hopAddress(
    pool: ManagedMixNodePool, node: ManagedNode, now: Moment
): Opt[MultiAddress] =
  ## Returns the first address of the node that the pool accepts, or none
  ## while the node is suspended.
  if node.suspendedUntil.isSome and now < node.suspendedUntil.get():
    return Opt.none(MultiAddress)
  for address in node.addresses:
    if pool.accepts(address):
      return Opt.some(address)
  Opt.none(MultiAddress)

method get*(
    pool: ManagedMixNodePool, peerId: PeerId
): Opt[MixPubInfo] {.gcsafe, raises: [].} =
  ## Returns the node as a mix hop, or none when it is suspended or has no
  ## address that the pool accepts.
  pool.nodes.withValue(peerId, node):
    let address = pool.hopAddress(node[], Moment.now()).valueOr:
      return Opt.none(MixPubInfo)
    return Opt.some(MixPubInfo.init(peerId, address, node.mixPubKey, node.libp2pPubKey))
  Opt.none(MixPubInfo)

method peerIds*(pool: ManagedMixNodePool): seq[PeerId] {.gcsafe, raises: [].} =
  ## Returns the nodes that a path can use now.
  let now = Moment.now()
  var usable: seq[PeerId]
  for peerId, node in pool.nodes:
    if pool.hopAddress(node, now).isSome:
      usable.add(peerId)
  usable

method len*(pool: ManagedMixNodePool): int {.gcsafe, raises: [].} =
  pool.peerIds().len

method remove*(pool: ManagedMixNodePool, peerId: PeerId): bool {.gcsafe, raises: [].} =
  if peerId notin pool.nodes:
    return false
  pool.nodes.del(peerId)
  pool.notify(peerId, false)
  true

proc evictAtLimit(pool: ManagedMixNodePool, now: Moment) =
  ## Remove one discovered node when the pool holds `maxDiscovered` of them.
  ## It removes a node that a path cannot use before the node with the oldest
  ## record.
  var count = 0
  var victim: Opt[PeerId]
  var victimRank: (bool, Moment)
  for peerId, node in pool.nodes:
    if node.source == MixNodeSource.Configured:
      continue
    count.inc()
    let nodeRank = (pool.hopAddress(node, now).isSome, node.lastSeen)
    if victim.isNone or nodeRank < victimRank:
      victim = Opt.some(peerId)
      victimRank = nodeRank
  if count >= pool.config.maxDiscovered and victim.isSome:
    discard pool.remove(victim.get())

proc add*(
    pool: ManagedMixNodePool,
    info: MixPubInfo,
    source: MixNodeSource,
    now = Moment.now(),
) =
  ## Add a node or change its record. A discovered record replaces the
  ## addresses of a discovered node and keeps the keys of a configured node.
  ## A configured record makes the node configured and ends its suspension.
  ## It puts its address first for a node that was discovered. For a configured
  ## node, it adds a new address at the end. The pool ignores a record for
  ## `selfId` and a record without a mix key.
  if info.peerId == pool.selfId or info.mixPubKey == default(Curve25519Key):
    return
  let joined = info.peerId notin pool.nodes
  if joined and source == MixNodeSource.Discovered:
    if pool.config.maxDiscovered <= 0:
      return
    pool.evictAtLimit(now)
  var node = pool.nodes.getOrDefault(info.peerId)
  let wasConfigured = not joined and node.source == MixNodeSource.Configured
  if joined or source == MixNodeSource.Configured:
    node.source = source
  if source == MixNodeSource.Configured:
    if not wasConfigured:
      # Put the configured address before the discovered ones.
      node.addresses = @[info.multiAddr] & node.addresses.filterIt(it != info.multiAddr)
    elif info.multiAddr notin node.addresses:
      node.addresses.add(info.multiAddr)
    node.suspendedUntil = Opt.none(Moment)
  elif node.source == MixNodeSource.Discovered:
    node.addresses = @[info.multiAddr]
  if source == MixNodeSource.Configured or node.source == MixNodeSource.Discovered:
    node.mixPubKey = info.mixPubKey
    node.libp2pPubKey = info.libp2pPubKey
  node.lastSeen = now
  pool.nodes[info.peerId] = node
  if joined:
    pool.notify(info.peerId, true)

method add*(pool: ManagedMixNodePool, info: MixPubInfo) {.gcsafe, raises: [].} =
  ## Add a configured node. It stays until `remove`.
  pool.add(info, MixNodeSource.Configured)

proc refresh*(pool: ManagedMixNodePool, peerId: PeerId, now = Moment.now()) =
  ## Set the record of a node to `now` and end its suspension, for example
  ## after a successful dial.
  pool.nodes.withValue(peerId, node):
    node.lastSeen = now
    node.suspendedUntil = Opt.none(Moment)

proc suspend*(pool: ManagedMixNodePool, peerId: PeerId, until: Moment) =
  ## Keep a node out of mix paths until `until`. The node stays in the pool.
  pool.nodes.withValue(peerId, node):
    node.suspendedUntil = Opt.some(until)

proc resume*(pool: ManagedMixNodePool, peerId: PeerId) =
  ## End the suspension of a node.
  pool.nodes.withValue(peerId, node):
    node.suspendedUntil = Opt.none(Moment)

proc maintain*(pool: ManagedMixNodePool, now = Moment.now()) =
  ## Remove each discovered node whose record is older than `discoveredTtl`,
  ## unless the `isConnected` check of the config returns true for it.
  ## End each suspension whose time has passed.
  let isConnected = pool.config.isConnected
  for peerId in pool.nodes.keys.toSeq():
    var expired = false
    pool.nodes.withValue(peerId, node):
      if node.source == MixNodeSource.Discovered:
        if not isConnected.isNil and isConnected(peerId):
          node.lastSeen = now
        expired = now - node.lastSeen >= pool.config.discoveredTtl
      if node.suspendedUntil.isSome and now >= node.suspendedUntil.get():
        node.suspendedUntil = Opt.none(Moment)
    if expired:
      discard pool.remove(peerId)

proc maintenanceLoopProc(
    pool: ManagedMixNodePool
) {.async: (raises: [CancelledError]).} =
  while true:
    await sleepAsync(pool.config.maintenanceInterval)
    pool.maintain()

proc start*(pool: ManagedMixNodePool) =
  ## Start the maintenance loop. A second call while it runs does nothing.
  if pool.maintenanceLoop.isNil or pool.maintenanceLoop.finished:
    pool.maintenanceLoop = pool.maintenanceLoopProc()

proc stop*(pool: ManagedMixNodePool) {.async: (raises: []).} =
  ## Stop the maintenance loop.
  if not pool.maintenanceLoop.isNil:
    await pool.maintenanceLoop.cancelAndWait()
    pool.maintenanceLoop = nil
