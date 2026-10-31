# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results, sequtils, sets
import libp2p/[crypto/crypto, crypto/secp, peerid, peerstore]
import libp2p_mix/[mix_node, pool, mix_pool, mix_protocol]
import ./tools/[unittest, crypto, host_pool]
import ./utils

type RepeatingPool = ref object of HostPool
  ## Lists every ID twice, as a host with duplicate records would.

method listPeerIds(
    pool: RepeatingPool
): Result[seq[PeerId], string] {.gcsafe, raises: [].} =
  let ids = ?procCall listPeerIds(HostPool(pool))
  ok(ids & ids)

type FailingPool = ref object of MixPool ## A pool that cannot answer.

method readPeer(
    pool: FailingPool, peerId: PeerId
): Result[MixPeerRecord, string] {.gcsafe, raises: [].} =
  err("read failed")

method listPeerIds(
    pool: FailingPool
): Result[seq[PeerId], string] {.gcsafe, raises: [].} =
  err("list failed")

suite "MixPool":
  test "the stock pool keeps its raw membership while routes skip incomplete peers":
    let store = PeerStore.new()
    let pool = MixNodePool.new(store)
    let infos = MixNodeInfo.generateRandomMany(3, rng()).mapIt(it.toMixPubInfo())
    pool.add(infos[0])
    store[MixPubKeyBook][infos[1].peerId] = infos[1].mixPubKey
    check pool.listPeerIds().get().len == 2
    check pool.countUsable([]).get() == 1
    check pool.countUsable([infos[0].peerId, infos[0].peerId]).get() == 0
    check pool.selectRandomNodes(rng(), 2, []).error.kind == LowPool
    check pool.selectRandomNodes(rng(), 1, []).get() == @[infos[0]]
    check store[MixPubKeyBook].len == 2

  test "an identity the wire format cannot encode is unusable and stays stored":
    let store = PeerStore.new()
    let pool = MixNodePool.new(store)
    var info = MixNodeInfo.generateRandom(9000, rng()).toMixPubInfo()
    info.peerId = PeerId()
    pool.add(info)
    check pool.usablePeer(info.peerId).get().isNone
    check pool.countUsable([]).get() == 0
    check pool.selectRandomNodes(rng(), 1, []).isErr
    check store[MixPubKeyBook].len == 1

  test "duplicate IDs count once and never repeat a hop":
    let pool = RepeatingPool(store: PeerStore.new())
    for node in MixNodeInfo.generateRandomMany(2, rng()):
      pool.addPeer(node.toMixPubInfo())
    check pool.listPeerIds().get().len == 4
    check pool.countUsable([]).get() == 2
    check pool.selectRandomNodes(rng(), 3, []).isErr
    for _ in 0 ..< 30:
      let selected = pool.selectRandomNodes(rng(), 2, []).get()
      check selected[0].peerId != selected[1].peerId

  test "host exclusions and recovery affect every routing query immediately":
    let pool = HostPool.new()
    let info = MixNodeInfo.generateRandom(9000, rng()).toMixPubInfo()
    pool.addPeer(info)
    pool.exclude(info.peerId)
    check pool.usablePeer(info.peerId).get().isNone
    check pool.listPeerIds().get().len == 0
    check pool.countUsable([]).get() == 0
    check pool.selectRandomNodes(rng(), 1, []).isErr
    check pool.store[MixPubKeyBook][info.peerId] == info.mixPubKey
    pool.restore(info.peerId)
    check pool.selectRandomNodes(rng(), 1, []).get() == @[info]

  test "a pool error fails every read and selection":
    let pool = FailingPool()
    let info = MixNodeInfo.generateRandom(0, rng()).toMixPubInfo()
    check pool.usablePeer(info.peerId).error.kind == PoolUnavailable
    check pool.countUsable([]).error.kind == PoolUnavailable
    check pool.selectRandomNodes(rng(), 1, []).error.kind == PoolUnavailable
    check (waitFor pool.selectReplyPeer(rng(), @[])).error.kind == PoolUnavailable

  test "the default reply selection takes one usable peer that is not excluded":
    let pool = HostPool.new()
    let infos = MixNodeInfo.generateRandomMany(3, rng()).mapIt(it.toMixPubInfo())
    for info in infos:
      pool.addPeer(info)
    var chosen: HashSet[PeerId]
    for _ in 0 ..< 32:
      let peer = (waitFor pool.selectReplyPeer(rng(), @[infos[0].peerId])).get()
      check peer in [infos[1].peerId, infos[2].peerId]
      chosen.incl(peer)
    check chosen.len == 2
    check (waitFor pool.selectReplyPeer(rng(), infos.mapIt(it.peerId))).error.kind ==
      LowPool
