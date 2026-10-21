# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import results, sequtils
import libp2p/[peerstore, peerid, multiaddress, crypto/crypto, crypto/secp]
import libp2p_mix/[pool, peer_selection, mix_node]
import ./tools/[unittest, crypto, peer_source]

suite "Common pool routing queries":
  test "the pool keeps its raw membership while routes skip incomplete peers":
    let store = PeerStore.new()
    let pool = MixNodePool.new(store)
    let infos = MixNodeInfo.generateRandomMany(3, rng()).mapIt(it.toMixPubInfo())
    pool.add(infos[0])
    store[MixPubKeyBook][infos[1].peerId] = infos[1].mixPubKey
    let ctx = poolPeerContext(store)
    check ctx.peerIds().get().len == 2
    check ctx.count([]).get() == 1
    check ctx.count([infos[0].peerId, infos[0].peerId]).get() == 0
    check ctx.selectRandomNodes(rng(), 2, []).isErr
    check ctx.selectRandomNodes(rng(), 1, []).get() == @[infos[0]]
    check store[MixPubKeyBook].len == 2
    check ctx.peerIds().get().len == 2

  test "both providers answer the same queries":
    let infos = MixNodeInfo.generateRandomMany(4, rng()).mapIt(it.toMixPubInfo())
    let contexts = @[poolPeerContext(), hostPeerContext()]
    for ctx in contexts:
      ctx.add(infos).get()
      let excluded = [infos[0].peerId, infos[0].peerId]
      check ctx.count(excluded).get() == 3
      let selected = ctx.selectRandomNodes(rng(), 3, excluded).get()
      check selected.len == 3
      check selected.mapIt(it.peerId).deduplicate().len == 3
      check selected.allIt(it.peerId != infos[0].peerId)
      check ctx.remove(infos[1].peerId).get()
      check ctx.get(infos[1].peerId).get().isNone
      check ctx.count(excluded).get() == 2
      check ctx.selectRandomNodes(rng(), 3, excluded).isErr

  test "selecting zero nodes from an empty pool does not use the RNG":
    let contexts = @[poolPeerContext(), HostPeerSource.new().brokerCtx]
    for ctx in contexts:
      check ctx.selectRandomNodes(rng(), 0, []).get().len == 0
      check ctx.selectRandomNodes(rng(), 1, []).isErr

  test "both providers keep the first key and every address on add":
    let source = HostPeerSource.new(allowAllAddresses = true)
    let owned = PeerStore.new()
    let cases: seq[tuple[ctx: BrokerContext, store: PeerStore]] =
      @[(poolPeerContext(owned), owned), (source.brokerCtx, source.store)]
    let infos = MixNodeInfo.generateRandomMany(2, rng()).mapIt(it.toMixPubInfo())
    for (ctx, store) in cases:
      ctx.add(infos[0]).get()
      var changed = infos[0]
      changed.mixPubKey = infos[1].mixPubKey
      changed.libp2pPubKey = infos[1].libp2pPubKey
      changed.multiAddr = MultiAddress.init("/ip4/127.0.0.1/tcp/9001").get()
      ctx.add(changed).get()
      check store[MixPubKeyBook][changed.peerId] == changed.mixPubKey
      check store[KeyBook][changed.peerId].skkey == infos[0].libp2pPubKey
      check infos[0].multiAddr in store[AddressBook][changed.peerId]
      check changed.multiAddr in store[AddressBook][changed.peerId]
      check ctx.get(changed.peerId).get().get().libp2pPubKey == infos[0].libp2pPubKey

  test "shared wire validation rejects an unencodable identity without deleting it":
    let source = HostPeerSource.new(allowAllAddresses = true)
    let owned = PeerStore.new()
    let cases: seq[tuple[ctx: BrokerContext, store: PeerStore]] =
      @[(poolPeerContext(owned), owned), (source.brokerCtx, source.store)]
    var info = MixNodeInfo.generateRandom(9000, rng()).toMixPubInfo()
    info.peerId = PeerId()
    for (ctx, store) in cases:
      ctx.add(info).get()
      check ctx.get(info.peerId).get().isNone
      check ctx.count([]).get() == 0
      check ctx.selectRandomNodes(rng(), 1, []).isErr
      check store[MixPubKeyBook].len == 1
