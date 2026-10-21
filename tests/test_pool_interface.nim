# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import results, sequtils
import libp2p/[peerstore, peerid, multiaddress, crypto/crypto, crypto/secp]
import libp2p_mix/[pool, mix_pool, mix_node]
import ./tools/[unittest, crypto, host_pool]

suite "Behavior shared by both pool classes":
  test "the stock pool keeps its raw membership while routes skip incomplete peers":
    let store = PeerStore.new()
    let pool = MixNodePool.new(store, rng())
    let infos = MixNodeInfo.generateRandomMany(3, rng()).mapIt(it.toMixPubInfo())
    pool.add(infos[0])
    store[MixPubKeyBook][infos[1].peerId] = infos[1].mixPubKey
    check pool.listPeerIds().get().len == 2
    check pool.countUsable([]).get() == 1
    check pool.countUsable([infos[0].peerId, infos[0].peerId]).get() == 0
    check pool.selectRandomNodes(2, []).isErr
    check pool.selectRandomNodes(1, []).get() == @[infos[0]]
    check store[MixPubKeyBook].len == 2
    check pool.listPeerIds().get().len == 2

  test "both pool classes answer the same queries":
    let infos = MixNodeInfo.generateRandomMany(4, rng()).mapIt(it.toMixPubInfo())
    let pools = @[MixPool(newStockPool()), MixPool(newHostPool())]
    for pool in pools:
      pool.addPeers(infos)
      let excluded = [infos[0].peerId, infos[0].peerId]
      check pool.countUsable(excluded).get() == 3
      let selected = pool.selectRandomNodes(3, excluded).get()
      check selected.len == 3
      check selected.mapIt(it.peerId).deduplicate().len == 3
      check selected.allIt(it.peerId != infos[0].peerId)
      check pool.removePeer(infos[1].peerId)
      check pool.usablePeer(infos[1].peerId).get().isNone
      check pool.countUsable(excluded).get() == 2
      check pool.selectRandomNodes(3, excluded).isErr

  test "selecting zero peers from an empty pool returns an empty list":
    let pools = @[MixPool(newStockPool()), MixPool(HostPool.new())]
    for pool in pools:
      check pool.selectRandomNodes(0, []).get().len == 0
      check pool.selectRandomNodes(1, []).isErr

  test "both pool classes keep the first key and every address on add":
    let host = HostPool.new(allowAllAddresses = true)
    let owned = PeerStore.new()
    let cases: seq[tuple[pool: MixPool, store: PeerStore]] =
      @[(MixPool(newStockPool(owned)), owned), (MixPool(host), host.store)]
    let infos = MixNodeInfo.generateRandomMany(2, rng()).mapIt(it.toMixPubInfo())
    for (pool, store) in cases:
      pool.addPeer(infos[0])
      var changed = infos[0]
      changed.mixPubKey = infos[1].mixPubKey
      changed.libp2pPubKey = infos[1].libp2pPubKey
      changed.multiAddr = MultiAddress.init("/ip4/127.0.0.1/tcp/9001").get()
      pool.addPeer(changed)
      check store[MixPubKeyBook][changed.peerId] == changed.mixPubKey
      check store[KeyBook][changed.peerId].skkey == infos[0].libp2pPubKey
      check infos[0].multiAddr in store[AddressBook][changed.peerId]
      check changed.multiAddr in store[AddressBook][changed.peerId]
      check pool.usablePeer(changed.peerId).get().get().libp2pPubKey ==
        infos[0].libp2pPubKey

  test "an identity the wire format cannot encode is unusable and stays stored":
    let host = HostPool.new(allowAllAddresses = true)
    let owned = PeerStore.new()
    let cases: seq[tuple[pool: MixPool, store: PeerStore]] =
      @[(MixPool(newStockPool(owned)), owned), (MixPool(host), host.store)]
    var info = MixNodeInfo.generateRandom(9000, rng()).toMixPubInfo()
    info.peerId = PeerId()
    for (pool, store) in cases:
      pool.addPeer(info)
      check pool.usablePeer(info.peerId).get().isNone
      check pool.countUsable([]).get() == 0
      check pool.selectRandomNodes(1, []).isErr
      check store[MixPubKeyBook].len == 1
