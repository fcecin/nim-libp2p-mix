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

suite "ManagedMixNodePool":
  var
    pool {.threadvar.}: ManagedMixNodePool
    infos {.threadvar.}: seq[MixPubInfo]
    base {.threadvar.}: Moment

  setup:
    pool = ManagedMixNodePool.new()
    infos = MixNodeInfo.generateRandomMany(6, rng()).mapIt(it.toMixPubInfo())
    base = Moment.now()

  test "add keeps a configured node and a discovered one":
    pool.add(infos[0])
    pool.add(infos[1], MixNodeSource.Discovered)
    check:
      pool.len == 2
      pool.source(infos[0].peerId) == Opt.some(MixNodeSource.Configured)
      pool.source(infos[1].peerId) == Opt.some(MixNodeSource.Discovered)
      pool.get(infos[0].peerId) == Opt.some(infos[0])
      pool.get(infos[1].peerId) == Opt.some(infos[1])

  test "a nil address policy accepts each address that the mix protocol supports":
    let nilPolicyPool = ManagedMixNodePool.new(ManagedPoolConfig(addressPolicy: nil))
    nilPolicyPool.add(infos[0])
    check nilPolicyPool.get(infos[0].peerId) == Opt.some(infos[0])

  test "a discovered record keeps the keys of a configured node":
    pool.add(infos[0])
    var other = infos[1]
    other.peerId = infos[0].peerId
    pool.add(other, MixNodeSource.Discovered)
    check:
      pool.source(infos[0].peerId) == Opt.some(MixNodeSource.Configured)
      pool.get(infos[0].peerId) == Opt.some(infos[0])

  test "a discovered node expires and a configured node stays":
    pool.add(infos[0], MixNodeSource.Discovered, now = base)
    pool.add(infos[1])
    pool.maintain(base + 30.minutes)
    check pool.len == 2
    pool.add(infos[0], MixNodeSource.Discovered, now = base + 50.minutes)
    pool.maintain(base + 1.hours)
    check pool.len == 2
    pool.maintain(base + 2.hours)
    check:
      pool.len == 1
      infos[0].peerId notin pool
      infos[1].peerId in pool

  test "the pool evicts the oldest discovered node at its limit":
    let small = ManagedMixNodePool.new(ManagedPoolConfig(maxDiscovered: 2))
    small.add(infos[0])
    small.add(infos[1], MixNodeSource.Discovered, now = base)
    small.add(infos[2], MixNodeSource.Discovered, now = base + 1.seconds)
    small.add(infos[3], MixNodeSource.Discovered, now = base + 2.seconds)
    check:
      small.len == 3
      infos[1].peerId notin small
      infos[0].peerId in small

  test "the pool evicts a node that paths cannot use before the oldest":
    let small = ManagedMixNodePool.new(ManagedPoolConfig(maxDiscovered: 2))
    small.add(infos[1], MixNodeSource.Discovered, now = base)
    small.add(infos[2], MixNodeSource.Discovered, now = base + 1.seconds)
    small.suspend(infos[2].peerId, Moment.now() + 1.hours)
    small.add(infos[3], MixNodeSource.Discovered, now = base + 2.seconds)
    check:
      infos[2].peerId notin small
      infos[1].peerId in small
      infos[3].peerId in small

  test "a connected discovered node does not expire":
    let kept = infos[0].peerId
    let checked = ManagedMixNodePool.new(
      ManagedPoolConfig(
        isConnected: proc(peerId: PeerId): bool {.gcsafe, raises: [].} =
          peerId == kept
      )
    )
    checked.add(infos[0], MixNodeSource.Discovered, now = base)
    checked.add(infos[1], MixNodeSource.Discovered, now = base)
    checked.maintain(base + 2.hours)
    check:
      infos[0].peerId in checked
      infos[1].peerId notin checked

  test "a configured add ends a suspension":
    pool.add(infos[0], MixNodeSource.Discovered)
    pool.suspend(infos[0].peerId, Moment.now() + 1.hours)
    check pool.len == 0
    pool.add(infos[0])
    check:
      pool.len == 1
      pool.suspendedUntil(infos[0].peerId).isNone
      pool.source(infos[0].peerId) == Opt.some(MixNodeSource.Configured)

  test "a configured add puts its address before a discovered one":
    var discovered = infos[0]
    discovered.multiAddr =
      MultiAddress.init("/ip4/127.0.0.1/tcp/4241").expect("could not create multiaddr")
    pool.add(discovered, MixNodeSource.Discovered)
    pool.add(infos[0])
    check pool.get(infos[0].peerId).get().multiAddr == infos[0].multiAddr

  test "a suspended node leaves paths until resume or the end of its suspension":
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
    pool.add(infos[0], MixNodeSource.Discovered, now = base)
    pool.suspend(infos[0].peerId, base + 1.hours)
    pool.refresh(infos[0].peerId, now = base + 50.minutes)
    check pool.suspendedUntil(infos[0].peerId).isNone
    pool.maintain(base + 1.hours)
    check pool.len == 1

  test "the address policy selects the hop address":
    let strictPool = ManagedMixNodePool.new(
      ManagedPoolConfig(addressPolicy: publicDirectAddressPolicy)
    )
    # `isPublicMA` refuses the documentation ranges, so this public address is outside them.
    let publicAddr = MultiAddress.init("/ip4/8.8.8.7/tcp/4243").tryGet()
    strictPool.add(infos[0])
    check strictPool.get(infos[0].peerId).isNone
    check strictPool.len == 0
    var reachable = infos[0]
    reachable.multiAddr = publicAddr
    strictPool.add(reachable)
    check strictPool.get(infos[0].peerId).get().multiAddr == publicAddr
    check strictPool.len == 1

  test "accepts through the base type uses the policy of the managed pool":
    let strictPool = ManagedMixNodePool.new(
      ManagedPoolConfig(addressPolicy: publicDirectAddressPolicy)
    )
    let basePool: MixNodePool = strictPool
    let privateAddr = MultiAddress.init("/ip4/192.168.1.1/tcp/4242").expect(
        "could not create multiaddr"
      )
    check:
      not strictPool.accepts(privateAddr)
      not basePool.accepts(privateAddr)

  test "the change handler sees each node that joins or leaves":
    var events: seq[(PeerId, bool)]
    let id = pool.addChangeHandler(
      proc(peerId: PeerId, present: bool) {.gcsafe, raises: [].} =
        events.add((peerId, present))
    )
    pool.add(infos[0])
    pool.add(infos[0])
    pool.add(infos[1], MixNodeSource.Discovered)
    check pool.remove(infos[0].peerId)
    check not pool.remove(infos[0].peerId)
    pool.removeChangeHandler(id)
    pool.add(infos[2], MixNodeSource.Discovered)
    check events ==
      @[(infos[0].peerId, true), (infos[1].peerId, true), (infos[0].peerId, false)]

  test "the pool ignores its own node and a record without a mix key":
    let own = ManagedMixNodePool.new(selfId = infos[0].peerId)
    own.add(infos[0])
    var blank = infos[1]
    blank.mixPubKey = default(typeof(blank.mixPubKey))
    own.add(blank, MixNodeSource.Discovered)
    check own.len == 0

  test "path building reads the managed pool":
    let nodeInfos = MixNodeInfo.generateRandomMany(5, rng())
    let node = MixProtocol.new(
      nodeInfos[0],
      createSwitch(nodeInfos[0].multiAddr, Opt.some(nodeInfos[0].libp2pPrivKey)),
    )
    let managed = ManagedMixNodePool.new(selfId = nodeInfos[0].peerId)
    node.nodePool = managed
    for info in nodeInfos:
      node.nodePool.add(info.toMixPubInfo())
    check node.nodePool.len == 4
    check node.switch.peerStore[MixPubKeyBook].len == 0
    let outsider = PeerId.random(rng()).tryGet()
    var id: SURBIdentifier
    rng().generate(id)
    check node.buildSurb(id, outsider, outsider).isOk
    managed.suspend(nodeInfos[1].peerId, Moment.now() + 1.hours)
    managed.suspend(nodeInfos[2].peerId, Moment.now() + 1.hours)
    check node.buildSurb(id, outsider, outsider).isErr

  asyncTest "the maintenance loop expires a discovered node":
    let quick = ManagedMixNodePool.new(
      ManagedPoolConfig(
        discoveredTtl: 50.milliseconds, maintenanceInterval: 10.milliseconds
      )
    )
    quick.add(infos[0], MixNodeSource.Discovered)
    quick.start()
    defer:
      await quick.stop()
    checkUntilTimeout:
      quick.len == 0
