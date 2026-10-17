# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import results, sequtils
import chronos
import libp2p/[crypto/crypto, crypto/secp, multiaddress, peerid, peerstore]
import libp2p_mix/[mix_node, pool, managed_pool, mix_protocol, serialization]
import ./tools/unittest
import ./tools/crypto
import ./utils

proc discover(store: PeerStore, info: MixPubInfo) =
  ## Writes a peer to the books as discovery does, the mix key last.
  store[AddressBook][info.peerId] = @[info.multiAddr]
  store[KeyBook][info.peerId] = PublicKey(scheme: Secp256k1, skkey: info.libp2pPubKey)
  store[MixPubKeyBook][info.peerId] = info.mixPubKey

proc address(text: string): MultiAddress =
  MultiAddress.init(text).expect("could not create multiaddr")

suite "ManagedMixNodePool":
  var
    store {.threadvar.}: PeerStore
    pool {.threadvar.}: ManagedMixNodePool
    infos {.threadvar.}: seq[MixPubInfo]
    selfId {.threadvar.}: PeerId
    base {.threadvar.}: Moment

  setup:
    store = PeerStore.new()
    selfId = PeerId.random(rng()).expect("could not generate peerId")
    pool = ManagedMixNodePool.new(store, selfId)
    infos = MixNodeInfo.generateRandomMany(6, rng()).mapIt(it.toMixPubInfo())
    base = Moment.now()

  test "a peer with a mix key in the peer store joins as a discovered member":
    store.discover(infos[0])
    check:
      infos[0].peerId in pool
      pool.source(infos[0].peerId) == Opt.some(MixNodeSource.Discovered)
      pool.get(infos[0].peerId) == Opt.some(infos[0])
      pool.len == 1

  test "a peer that has a mix key before the pool exists joins at the start":
    let early = PeerStore.new()
    early.discover(infos[0])
    let late = ManagedMixNodePool.new(early, selfId)
    check late.get(infos[0].peerId) == Opt.some(infos[0])

  test "a member gets its address and keys from the books as the base pool does":
    store.discover(infos[0])
    let bookAddr = address("/ip4/10.0.0.2/tcp/4242")
    let lastSeenAddr = address("/ip4/10.0.0.3/tcp/4243")
    store[AddressBook][infos[0].peerId] = @[bookAddr]
    check pool.get(infos[0].peerId).get().multiAddr == bookAddr
    store[LastSeenOutboundBook][infos[0].peerId] = Opt.some(lastSeenAddr)
    check pool.get(infos[0].peerId).get().multiAddr == lastSeenAddr
    store[MixPubKeyBook][infos[0].peerId] = infos[1].mixPubKey
    check pool.get(infos[0].peerId).get().mixPubKey == infos[1].mixPubKey

  test "a discovered member stays when the peer store deletes the peer":
    store.discover(infos[0])
    check pool.get(infos[0].peerId) == Opt.some(infos[0])
    store.del(infos[0].peerId)
    check:
      infos[0].peerId in pool
      pool.get(infos[0].peerId) == Opt.some(infos[0])
      pool.len == 1

  test "a discovered member keeps its data when its mix key comes before its addresses":
    store[MixPubKeyBook][infos[0].peerId] = infos[0].mixPubKey
    store[AddressBook][infos[0].peerId] = @[infos[0].multiAddr]
    store[KeyBook][infos[0].peerId] =
      PublicKey(scheme: Secp256k1, skkey: infos[0].libp2pPubKey)
    store.del(infos[0].peerId)
    check pool.get(infos[0].peerId) == Opt.some(infos[0])

  test "a configured member gets the addresses of the books":
    pool.add(infos[0])
    let lastSeenAddr = address("/ip4/10.0.0.3/tcp/4243")
    store[LastSeenOutboundBook][infos[0].peerId] = Opt.some(lastSeenAddr)
    check:
      pool.source(infos[0].peerId) == Opt.some(MixNodeSource.Configured)
      pool.get(infos[0].peerId).get().multiAddr == lastSeenAddr

  test "a discovered member expires and a configured member stays":
    store.discover(infos[0])
    pool.add(infos[1])
    pool.maintain(Moment.now() + 30.minutes)
    check pool.len == 2
    pool.maintain(Moment.now() + 2.hours)
    check:
      pool.len == 1
      infos[0].peerId notin pool
      infos[1].peerId in pool

  test "a mix key write renews a discovered member":
    store.discover(infos[0])
    pool.refresh(infos[0].peerId, now = base - 50.minutes)
    store[MixPubKeyBook][infos[0].peerId] = infos[0].mixPubKey
    pool.maintain(base + 30.minutes)
    check infos[0].peerId in pool

  test "the pool evicts the oldest discovered member at its limit":
    let small =
      ManagedMixNodePool.new(store, selfId, ManagedPoolConfig(maxDiscovered: 2))
    small.add(infos[0])
    store.discover(infos[1])
    store.discover(infos[2])
    small.refresh(infos[1].peerId, now = base - 2.minutes)
    small.refresh(infos[2].peerId, now = base - 1.minutes)
    store.discover(infos[3])
    check:
      small.len == 3
      infos[1].peerId notin small
      infos[0].peerId in small

  test "the pool evicts a member with no node data before the oldest":
    let small =
      ManagedMixNodePool.new(store, selfId, ManagedPoolConfig(maxDiscovered: 2))
    store.discover(infos[1])
    small.refresh(infos[1].peerId, now = base - 1.minutes)
    store[MixPubKeyBook][infos[2].peerId] = infos[2].mixPubKey
    store.discover(infos[3])
    check:
      infos[2].peerId notin small
      infos[1].peerId in small
      infos[3].peerId in small

  test "a connected discovered member does not expire":
    let kept = infos[0].peerId
    let checked = ManagedMixNodePool.new(
      store,
      selfId,
      ManagedPoolConfig(
        isConnected: proc(peerId: PeerId): bool {.gcsafe, raises: [].} =
          peerId == kept
      ),
    )
    store.discover(infos[0])
    store.discover(infos[1])
    checked.maintain(Moment.now() + 2.hours)
    check:
      infos[0].peerId in checked
      infos[1].peerId notin checked

  test "a configured add ends a suspension":
    store.discover(infos[0])
    pool.suspend(infos[0].peerId, Moment.now() + 1.hours)
    check pool.len == 0
    pool.add(infos[0])
    check:
      pool.len == 1
      pool.suspendedUntil(infos[0].peerId).isNone
      pool.source(infos[0].peerId) == Opt.some(MixNodeSource.Configured)

  test "a suspended member leaves paths until resume or the end of its suspension":
    pool.add(infos[0])
    pool.add(infos[1])
    pool.suspend(infos[0].peerId, Moment.now() + 1.hours)
    check:
      pool.len == 1
      pool.get(infos[0].peerId).isNone
      infos[0].peerId in pool
      infos[0].peerId notin pool.peerIds()
      infos[0].peerId in pool.allPeerIds()
    pool.resume(infos[0].peerId)
    check pool.len == 2
    pool.suspend(infos[0].peerId, base + 1.minutes)
    pool.maintain(base + 2.minutes)
    check pool.suspendedUntil(infos[0].peerId).isNone
    check pool.len == 2

  test "refresh sets the record to now and ends the suspension":
    store.discover(infos[0])
    pool.refresh(infos[0].peerId, now = base - 50.minutes)
    pool.suspend(infos[0].peerId, base + 1.hours)
    pool.refresh(infos[0].peerId, now = base)
    check pool.suspendedUntil(infos[0].peerId).isNone
    pool.maintain(base + 30.minutes)
    check pool.len == 1

  test "the address policy of the pool selects the hop address":
    let strictPool =
      ManagedMixNodePool.new(store, selfId, addressPolicy = publicDirectAddressPolicy)
    # `isPublicMA` refuses the documentation ranges, so this public address is outside them.
    let publicAddr = address("/ip4/8.8.8.7/tcp/4243")
    var privateInfo = infos[0]
    privateInfo.multiAddr = address("/ip4/192.168.1.1/tcp/4242")
    store.discover(privateInfo)
    check:
      strictPool.get(infos[0].peerId).isNone
      strictPool.len == 0
    store[AddressBook][infos[0].peerId] = @[privateInfo.multiAddr, publicAddr]
    check:
      strictPool.get(infos[0].peerId).get().multiAddr == publicAddr
      strictPool.len == 1

  test "the change handler sees each member that joins or leaves":
    var events: seq[(PeerId, bool)]
    let id = pool.addChangeHandler(
      proc(peerId: PeerId, present: bool) {.gcsafe, raises: [].} =
        events.add((peerId, present))
    )
    pool.add(infos[0])
    pool.add(infos[0])
    store.discover(infos[1])
    check pool.remove(infos[0].peerId)
    check not pool.remove(infos[0].peerId)
    pool.removeChangeHandler(id)
    store.discover(infos[2])
    check events ==
      @[(infos[0].peerId, true), (infos[1].peerId, true), (infos[0].peerId, false)]

  test "remove also deletes the mix key, as in the base pool":
    store.discover(infos[0])
    check pool.remove(infos[0].peerId)
    check:
      infos[0].peerId notin pool
      store[MixPubKeyBook][infos[0].peerId] == default(typeof(infos[0].mixPubKey))

  test "the pool ignores its own node and a node without a mix key":
    var own = infos[0]
    own.peerId = selfId
    pool.add(own)
    store.discover(own)
    var blank = infos[1]
    blank.mixPubKey = default(typeof(blank.mixPubKey))
    pool.add(blank)
    check pool.len == 0

  test "path building reads the managed pool":
    let nodeInfos = MixNodeInfo.generateRandomMany(5, rng())
    let node = MixProtocol.new(
      nodeInfos[0],
      createSwitch(nodeInfos[0].multiAddr, Opt.some(nodeInfos[0].libp2pPrivKey)),
    )
    let managed = ManagedMixNodePool.new(node.switch.peerStore, nodeInfos[0].peerId)
    node.nodePool = managed
    for info in nodeInfos:
      node.nodePool.add(info.toMixPubInfo())
    check node.nodePool.len == 4
    let outsider = PeerId.random(rng()).tryGet()
    var id: SURBIdentifier
    rng().generate(id)
    check node.buildSurb(id, outsider, outsider).isOk
    managed.suspend(nodeInfos[1].peerId, Moment.now() + 1.hours)
    managed.suspend(nodeInfos[2].peerId, Moment.now() + 1.hours)
    check node.buildSurb(id, outsider, outsider).isErr

  asyncTest "the maintenance loop expires a discovered member":
    let quick = ManagedMixNodePool.new(
      store,
      selfId,
      ManagedPoolConfig(
        discoveredTtl: 50.milliseconds, maintenanceInterval: 10.milliseconds
      ),
    )
    store.discover(infos[0])
    quick.start()
    defer:
      await quick.stop()
    checkUntilTimeout:
      quick.len == 0
