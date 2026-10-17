# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Managed Mix Node Pool
##
## An optional pool that adds a lifecycle to `MixNodePool`. It reads the data
## of each node as the base pool does: the record of a node added through
## `add`, the last outbound address, the address book, the key book and the
## mix key book. It also keeps its own list of members:
##
## - A peer joins as a discovered member when the peer store gets a mix key
##   for it. A later mix key write renews its record.
## - A node added through `add` is a configured member. It stays until
##   `remove`.
## - A discovered member stays when the peer store deletes the peer. It leaves
##   when its record is older than `discoveredTtl`, or when the pool holds
##   `maxDiscovered` discovered members and a newer one joins.
## - A suspended member stays in the pool and leaves mix paths until its
##   suspension ends.
##
## A change handler sees each member that joins or leaves. The protocol reads
## the pool through `MixNodePool`. An application sets `mixProto.nodePool` to a
## managed pool after it creates the protocol, and it calls `start` and `stop`
## for the maintenance loop.

{.push raises: [].}

import std/[sequtils, tables]
import chronos, results
import libp2p/[peerid, peerstore, peeraddrpolicy]
import libp2p/crypto/curve25519
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
    discoveredTtl*: Duration = 1.hours
    maxDiscovered*: int = 1000
    maintenanceInterval*: Duration = 15.seconds
    isConnected*: MixConnectionCheck
      ## When set, `maintain` renews a discovered member with a connection. A
      ## nil check renews no member.

  ManagedPoolChangeHandler* = proc(peerId: PeerId, present: bool) {.gcsafe, raises: [].}
    ## Called with `present` true when a member joins the pool and false when
    ## it leaves.

  Member = object
    source: MixNodeSource
    lastSeen: Moment
    suspendedUntil: Opt[Moment]
    lastInfo: Opt[MixPubInfo]
      ## The last node data that the base pool gave. The pool reads it again at
      ## each write to a book of the member. `get` returns it when the peer store
      ## has no mix key for the member.

  ManagedMixNodePool* = ref object of MixNodePool
    config: ManagedPoolConfig
    store: PeerStore
    selfId: PeerId
    members: Table[PeerId, Member]
    handlers: Table[uint64, ManagedPoolChangeHandler]
    lastHandlerId: uint64
    maintenanceLoop: Future[void]

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
  ## Returns true when the node is a member, suspended or not.
  peerId in pool.members

func allPeerIds*(pool: ManagedMixNodePool): seq[PeerId] =
  ## Returns every member, suspended or not. `peerIds` returns the members that
  ## a path can use now.
  pool.members.keys.toSeq()

func source*(pool: ManagedMixNodePool, peerId: PeerId): Opt[MixNodeSource] =
  pool.members.withValue(peerId, member):
    return Opt.some(member.source)
  Opt.none(MixNodeSource)

func suspendedUntil*(pool: ManagedMixNodePool, peerId: PeerId): Opt[Moment] =
  ## Returns the end of the suspension of the member, or none. A time that has
  ## passed stays until the next `maintain`.
  pool.members.withValue(peerId, member):
    return member.suspendedUntil
  Opt.none(Moment)

proc nodeData(pool: ManagedMixNodePool, peerId: PeerId): Opt[MixPubInfo] =
  ## Returns the data of a member as the base pool reads it, or the last data
  ## that the base pool gave when the peer store has no mix key for it.
  let info = procCall MixNodePool(pool).get(peerId)
  pool.members.withValue(peerId, member):
    if info.isSome:
      member.lastInfo = info
      return info
    if pool.store[MixPubKeyBook][peerId] == default(Curve25519Key) and
        member.lastInfo.isSome and pool.accepts(member.lastInfo.get().multiAddr):
      return member.lastInfo
  Opt.none(MixPubInfo)

method get*(
    pool: ManagedMixNodePool, peerId: PeerId
): Opt[MixPubInfo] {.gcsafe, raises: [].} =
  ## Returns the member as a mix hop, as the base pool reads it, or none when it
  ## is not a member or is suspended. When the peer store has no mix key for the
  ## member, it returns the last data that the base pool gave.
  pool.members.withValue(peerId, member):
    if member.suspendedUntil.isSome and Moment.now() < member.suspendedUntil.get():
      return Opt.none(MixPubInfo)
    return pool.nodeData(peerId)
  Opt.none(MixPubInfo)

method peerIds*(pool: ManagedMixNodePool): seq[PeerId] {.gcsafe, raises: [].} =
  ## Returns the members that a path can use now.
  pool.allPeerIds().filterIt(pool.get(it).isSome)

proc drop(pool: ManagedMixNodePool, peerId: PeerId) =
  ## Removes a member and leaves the peer store as it is.
  pool.members.del(peerId)
  pool.notify(peerId, false)

proc evictAtLimit(pool: ManagedMixNodePool) =
  ## Removes one discovered member when the pool holds `maxDiscovered` of them.
  ## It removes a member with no node data before the member with the oldest
  ## record. A suspension does not count, so a suspended member keeps it.
  var count = 0
  var victim: Opt[PeerId]
  var victimRank: (bool, Moment)
  for peerId in pool.allPeerIds():
    let member = pool.members.getOrDefault(peerId)
    if member.source == MixNodeSource.Configured:
      continue
    count.inc()
    let rank = (pool.nodeData(peerId).isSome, member.lastSeen)
    if victim.isNone or rank < victimRank:
      victim = Opt.some(peerId)
      victimRank = rank
  if count >= pool.config.maxDiscovered and victim.isSome:
    pool.drop(victim.get())

proc keepData(pool: ManagedMixNodePool, peerId: PeerId) =
  ## Reads the node data of a member again after a write to one of its books, so
  ## the last data stays when the peer store deletes the peer later.
  if peerId in pool.members:
    discard pool.nodeData(peerId)

proc learn(pool: ManagedMixNodePool, peerId: PeerId) =
  ## Adds a discovered member, or renews the record of a member, when the peer
  ## store gets a mix key for the peer. A deleted mix key keeps the member.
  let mixPubKey = pool.store[MixPubKeyBook][peerId]
  if peerId == pool.selfId or mixPubKey == default(Curve25519Key):
    return
  let now = Moment.now()
  pool.members.withValue(peerId, member):
    member.lastSeen = now
    return
  if pool.config.maxDiscovered <= 0:
    return
  pool.evictAtLimit()
  pool.members[peerId] = Member(source: MixNodeSource.Discovered, lastSeen: now)
  pool.keepData(peerId)
  pool.notify(peerId, true)

proc new*(
    T: typedesc[ManagedMixNodePool],
    peerStore: PeerStore,
    selfId: PeerId,
    config = ManagedPoolConfig(),
    addressPolicy: PeerAddressPolicy = defaultAddressPolicy,
): T =
  ## Create a managed pool on the peer store of the switch. Each peer that
  ## already has a mix key joins as a discovered member. The pool never holds
  ## `selfId`.
  doAssert config.maintenanceInterval > ZeroDuration,
    "maintenanceInterval must be positive"
  doAssert config.maxDiscovered >= 0, "maxDiscovered must not be negative"
  let pool = T(config: config, store: peerStore, selfId: selfId)
  pool.init(peerStore, addressPolicy)
  let book = peerStore[MixPubKeyBook]
  book.addHandler(
    proc(peerId: PeerId) {.gcsafe, raises: [].} =
      pool.learn(peerId)
  )
  let onData = proc(peerId: PeerId) {.gcsafe, raises: [].} =
    pool.keepData(peerId)
  peerStore[AddressBook].addHandler(onData)
  peerStore[LastSeenOutboundBook].addHandler(onData)
  peerStore[KeyBook].addHandler(onData)
  for peerId in book.book.keys.toSeq():
    pool.learn(peerId)
  pool

method add*(pool: ManagedMixNodePool, info: MixPubInfo) {.gcsafe, raises: [].} =
  ## Adds a configured member, or makes a member configured and ends its
  ## suspension. The base pool keeps the record of the node and writes its
  ## books. The pool ignores a node with `selfId` and a node without a mix key.
  if info.peerId == pool.selfId or info.mixPubKey == default(Curve25519Key):
    return
  let joined = info.peerId notin pool.members
  # The member comes first, so the mix key write renews it and adds no
  # discovered member.
  pool.members.withValue(info.peerId, member):
    member.source = MixNodeSource.Configured
    member.suspendedUntil = Opt.none(Moment)
  do:
    pool.members[info.peerId] =
      Member(source: MixNodeSource.Configured, lastSeen: Moment.now())
  procCall MixNodePool(pool).add(info)
  if joined:
    pool.notify(info.peerId, true)

method remove*(pool: ManagedMixNodePool, peerId: PeerId): bool {.gcsafe, raises: [].} =
  ## Removes a member. The base pool also deletes its record and its mix key, as
  ## for a node of the base pool.
  let present = peerId in pool.members
  pool.members.del(peerId)
  let inBase = procCall MixNodePool(pool).remove(peerId)
  if present:
    pool.notify(peerId, false)
  present or inBase

proc refresh*(pool: ManagedMixNodePool, peerId: PeerId, now = Moment.now()) =
  ## Set the record of a member to `now` and end its suspension, for example
  ## after a successful dial.
  pool.members.withValue(peerId, member):
    member.lastSeen = now
    member.suspendedUntil = Opt.none(Moment)

proc suspend*(pool: ManagedMixNodePool, peerId: PeerId, until: Moment) =
  ## Keep a member out of mix paths until `until`. The member stays in the pool.
  pool.members.withValue(peerId, member):
    member.suspendedUntil = Opt.some(until)

proc resume*(pool: ManagedMixNodePool, peerId: PeerId) =
  ## End the suspension of a member.
  pool.members.withValue(peerId, member):
    member.suspendedUntil = Opt.none(Moment)

proc maintain*(pool: ManagedMixNodePool, now = Moment.now()) =
  ## Remove each discovered member whose record is older than `discoveredTtl`,
  ## unless the `isConnected` check of the config returns true for it. End each
  ## suspension whose time has passed.
  let isConnected = pool.config.isConnected
  for peerId in pool.allPeerIds():
    var expired = false
    pool.members.withValue(peerId, member):
      if member.source == MixNodeSource.Discovered:
        if not isConnected.isNil and isConnected(peerId):
          member.lastSeen = now
        expired = now - member.lastSeen >= pool.config.discoveredTtl
      if member.suspendedUntil.isSome and now >= member.suspendedUntil.get():
        member.suspendedUntil = Opt.none(Moment)
    if expired:
      pool.drop(peerId)

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
