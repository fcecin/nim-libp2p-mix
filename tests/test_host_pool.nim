# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results, sequtils
import libp2p/[crypto/crypto, crypto/secp, multiaddress, peerid, peerstore]
import libp2p_mix/[mix_node, pool, mix_pool, mix_protocol]
import ./tools/[unittest, host_pool]
import ./tools/crypto
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

suite "Host pool storage":
  var
    peerStore {.threadvar.}: PeerStore
    pool {.threadvar.}: HostPool
    mixNodes {.threadvar.}: seq[MixNodeInfo]

  setup:
    peerStore = PeerStore.new()
    pool = HostPool.new(allowAllAddresses = true, store = peerStore)
    mixNodes = MixNodeInfo.generateRandomMany(5, rng())

  test "new creates an empty store":
    check pool.listPeerIds().get().len == 0

  test "add stores mix node info":
    let pubInfo = mixNodes[0].toMixPubInfo()

    pool.addPeer(pubInfo)

    check:
      pool.listPeerIds().get().len == 1
      pool.usablePeer(pubInfo.peerId).get().isSome
      pool.usablePeer(pubInfo.peerId).get().get() == pubInfo

  test "add stores all required data in peerStore":
    let pubInfo = mixNodes[0].toMixPubInfo()

    pool.addPeer(pubInfo)

    check:
      peerStore[MixPubKeyBook][pubInfo.peerId] == pubInfo.mixPubKey
      peerStore[AddressBook][pubInfo.peerId] == @[pubInfo.multiAddr]
      peerStore[KeyBook][pubInfo.peerId].scheme == Secp256k1
      peerStore[KeyBook][pubInfo.peerId].skkey == pubInfo.libp2pPubKey

  test "bulk add stores multiple mix nodes":
    let pubInfos = mixNodes.mapIt(it.toMixPubInfo())

    pool.addPeers(pubInfos)

    check pool.listPeerIds().get().len == mixNodes.len
    for pubInfo in pubInfos:
      check pool.usablePeer(pubInfo.peerId).get().isSome
      check pool.usablePeer(pubInfo.peerId).get().get() == pubInfo

  test "bulk add with empty seq is no-op":
    pool.addPeers(newSeq[MixPubInfo]())
    check pool.listPeerIds().get().len == 0

  test "remove deletes from the store":
    let pubInfo = mixNodes[0].toMixPubInfo()

    pool.addPeer(pubInfo)
    check pool.listPeerIds().get().len == 1

    let removed = pool.removePeer(pubInfo.peerId)

    check:
      removed == true
      pool.listPeerIds().get().len == 0
      pool.usablePeer(pubInfo.peerId).get().isNone

  test "remove returns false for non-existent peer":
    let peerId = PeerId.random(rng()).expect("could not generate peerId")
    check pool.removePeer(peerId) == false

  test "get returns none for non-existent peer":
    let peerId = PeerId.random(rng()).expect("could not generate peerId")
    check pool.usablePeer(peerId).get().isNone

  test "get returns none when address is missing":
    let pubInfo = mixNodes[0].toMixPubInfo()

    # Manually add only the mix key, not the address
    peerStore[MixPubKeyBook][pubInfo.peerId] = pubInfo.mixPubKey

    check pool.usablePeer(pubInfo.peerId).get().isNone

  test "get returns none when key scheme is not Secp256k1":
    let pubInfo = mixNodes[0].toMixPubInfo()

    # Manually add with wrong key scheme
    peerStore[MixPubKeyBook][pubInfo.peerId] = pubInfo.mixPubKey
    peerStore[AddressBook][pubInfo.peerId] = @[pubInfo.multiAddr]
    # KeyBook is not set, so scheme defaults to something other than Secp256k1

    check pool.usablePeer(pubInfo.peerId).get().isNone

  test "get filters for supported addresses (IPv4 with TCP or QUIC-v1)":
    let pubInfo = mixNodes[0].toMixPubInfo()
    let relayPeerId = PeerId.random(rng()).expect("could not generate relay peerId")
    let ipv6Addr =
      MultiAddress.init("/ip6/::1/tcp/4242").expect("could not create multiaddr")
    let udpAddr =
      MultiAddress.init("/ip4/127.0.0.1/udp/4242").expect("could not create multiaddr")
    let tcpAddr =
      MultiAddress.init("/ip4/127.0.0.1/tcp/4243").expect("could not create multiaddr")
    let quicAddr = MultiAddress.init("/ip4/127.0.0.1/udp/4244/quic-v1").expect(
        "could not create multiaddr"
      )
    # Circuit-relay addresses
    let tcpCircuitAddr = MultiAddress
      .init("/ip4/127.0.0.1/tcp/4245/p2p/" & $relayPeerId & "/p2p-circuit")
      .expect("could not create multiaddr")
    let quicCircuitAddr = MultiAddress
      .init("/ip4/127.0.0.1/udp/4246/quic-v1/p2p/" & $relayPeerId & "/p2p-circuit")
      .expect("could not create multiaddr")
    let ipv6CircuitAddr = MultiAddress
      .init("/ip6/::1/tcp/4247/p2p/" & $relayPeerId & "/p2p-circuit")
      .expect("could not create multiaddr")

    peerStore[MixPubKeyBook][pubInfo.peerId] = pubInfo.mixPubKey
    peerStore[KeyBook][pubInfo.peerId] =
      PublicKey(scheme: Secp256k1, skkey: pubInfo.libp2pPubKey)

    # Only IPv6 - should return none
    peerStore[AddressBook][pubInfo.peerId] = @[ipv6Addr]
    check pool.usablePeer(pubInfo.peerId).get().isNone

    # Only UDP (without QUIC-v1) - should return none
    peerStore[AddressBook][pubInfo.peerId] = @[udpAddr]
    check pool.usablePeer(pubInfo.peerId).get().isNone

    # IPv6 and UDP first, then TCP - should return TCP
    peerStore[AddressBook][pubInfo.peerId] = @[ipv6Addr, udpAddr, tcpAddr]
    check pool.usablePeer(pubInfo.peerId).get().get().multiAddr == tcpAddr

    # UDP first, then QUIC-v1 - should return QUIC-v1
    peerStore[AddressBook][pubInfo.peerId] = @[udpAddr, quicAddr]
    check pool.usablePeer(pubInfo.peerId).get().get().multiAddr == quicAddr

    # TCP and QUIC-v1 both available - should return first match (TCP)
    peerStore[AddressBook][pubInfo.peerId] = @[tcpAddr, quicAddr]
    check pool.usablePeer(pubInfo.peerId).get().get().multiAddr == tcpAddr

    # TCP circuit-relay - should be supported
    peerStore[AddressBook][pubInfo.peerId] = @[tcpCircuitAddr]
    check pool.usablePeer(pubInfo.peerId).get().get().multiAddr == tcpCircuitAddr

    # QUIC-v1 circuit-relay - should be supported
    peerStore[AddressBook][pubInfo.peerId] = @[quicCircuitAddr]
    check pool.usablePeer(pubInfo.peerId).get().get().multiAddr == quicCircuitAddr

    # IPv6 circuit-relay - should return none (unsupported transport)
    peerStore[AddressBook][pubInfo.peerId] = @[ipv6CircuitAddr]
    check pool.usablePeer(pubInfo.peerId).get().isNone

    # Mixed: unsupported circuit-relay first, then supported - should return supported
    peerStore[AddressBook][pubInfo.peerId] = @[ipv6CircuitAddr, tcpCircuitAddr]
    check pool.usablePeer(pubInfo.peerId).get().get().multiAddr == tcpCircuitAddr

  test "listPeerIds returns all peer IDs":
    for i in 0 ..< mixNodes.len:
      let pubInfo = mixNodes[i].toMixPubInfo()
      pool.addPeer(pubInfo)

    let peerIds = pool.listPeerIds().get()

    check peerIds.len == mixNodes.len

    for i in 0 ..< mixNodes.len:
      let pubInfo = mixNodes[i].toMixPubInfo()
      check pubInfo.peerId in peerIds

  test "duplicate IDs count once and never repeat a hop":
    let repeating = RepeatingPool(store: peerStore, allowAllAddresses: true, rng: rng())
    repeating.addPeers(@[mixNodes[0].toMixPubInfo(), mixNodes[1].toMixPubInfo()])
    check repeating.listPeerIds().get().len == 4
    check repeating.countUsable([]).get() == 2
    check repeating.selectRandomNodes(3, []).isErr
    for _ in 0 ..< 30:
      let selected = repeating.selectRandomNodes(2, []).get()
      check selected[0].peerId != selected[1].peerId

  test "listPeerIds counts the stored peers":
    check pool.listPeerIds().get().len == 0

    for i in 0 ..< 3:
      let pubInfo = mixNodes[i].toMixPubInfo()
      pool.addPeer(pubInfo)
      check pool.listPeerIds().get().len == i + 1

  test "get prefers LastSeenOutboundBook over AddressBook":
    let pubInfo = mixNodes[0].toMixPubInfo()
    let addressBookAddr = MultiAddress.init("/ip4/192.168.1.1/tcp/4242").expect(
        "could not create multiaddr"
      )
    let lastSeenAddr =
      MultiAddress.init("/ip4/10.0.0.1/tcp/4243").expect("could not create multiaddr")
    let lastSeenIpv6Addr =
      MultiAddress.init("/ip6/::1/tcp/4244").expect("could not create multiaddr")

    peerStore[MixPubKeyBook][pubInfo.peerId] = pubInfo.mixPubKey
    peerStore[KeyBook][pubInfo.peerId] =
      PublicKey(scheme: Secp256k1, skkey: pubInfo.libp2pPubKey)
    peerStore[AddressBook][pubInfo.peerId] = @[addressBookAddr]

    # When LastSeenOutboundBook has a supported address, prefer it
    peerStore[LastSeenOutboundBook][pubInfo.peerId] = Opt.some(lastSeenAddr)
    check pool.usablePeer(pubInfo.peerId).get().get().multiAddr == lastSeenAddr

    # When LastSeenOutboundBook has unsupported address (IPv6), fall back to AddressBook
    peerStore[LastSeenOutboundBook][pubInfo.peerId] = Opt.some(lastSeenIpv6Addr)
    check pool.usablePeer(pubInfo.peerId).get().get().multiAddr == addressBookAddr

    # When LastSeenOutboundBook is empty, fall back to AddressBook
    peerStore[LastSeenOutboundBook][pubInfo.peerId] = Opt.none(MultiAddress)
    check pool.usablePeer(pubInfo.peerId).get().get().multiAddr == addressBookAddr

  test "multiple operations sequence":
    # Add 3 nodes
    for i in 0 ..< 3:
      let pubInfo = mixNodes[i].toMixPubInfo()
      pool.addPeer(pubInfo)

    check pool.listPeerIds().get().len == 3

    # Remove middle node
    let middlePubInfo = mixNodes[1].toMixPubInfo()
    discard pool.removePeer(middlePubInfo.peerId)

    check:
      pool.listPeerIds().get().len == 2
      pool.usablePeer(middlePubInfo.peerId).get().isNone

    # Add two more nodes
    for i in 3 ..< 5:
      let pubInfo = mixNodes[i].toMixPubInfo()
      pool.addPeer(pubInfo)

    check pool.listPeerIds().get().len == 4

suite "Host pool policy":
  test "the host changes its address policy with no library option":
    let pool = HostPool.new()
    let info = MixNodeInfo.generateRandom(9000, rng()).toMixPubInfo()
    pool.addPeer(info)
    check pool.store[AddressBook][info.peerId] == @[info.multiAddr]
    check pool.usablePeer(info.peerId).get().isNone
    check pool.countUsable([]).get() == 0
    pool.allowAllAddresses = true
    check pool.usablePeer(info.peerId).get() == Opt.some(info)
    check pool.countUsable([]).get() == 1
    pool.allowAllAddresses = false
    check pool.countUsable([]).get() == 0

  test "host-approved outbound and fallback addresses follow one rule":
    let pool = HostPool.new()
    var info = MixNodeInfo.generateRandom(9000, rng()).toMixPubInfo()
    info.multiAddr = MultiAddress.init("/ip4/8.8.8.8/tcp/9000").get()
    pool.addPeer(info)
    pool.store[LastSeenOutboundBook][info.peerId] =
      Opt.some(MultiAddress.init("/ip4/127.0.0.1/tcp/9001").get())
    check pool.usablePeer(info.peerId).get().get().multiAddr == info.multiAddr
    let publicQuic = MultiAddress.init("/ip4/8.8.4.4/udp/9001/quic-v1").get()
    pool.store[LastSeenOutboundBook][info.peerId] = Opt.some(publicQuic)
    check pool.usablePeer(info.peerId).get().get().multiAddr == publicQuic

  test "strict filtering belongs to the host and keeps the rejected addresses":
    let pool = HostPool.new()
    var info = MixNodeInfo.generateRandom(9000, rng()).toMixPubInfo()
    let relay = PeerId.random(rng()).get()
    for text in [
      "/ip4/127.0.0.1/tcp/9000",
      "/ip4/0.0.0.0/tcp/9000",
      "/ip4/192.168.1.1/tcp/9000",
      "/ip4/8.8.8.8/tcp/0",
      "/ip4/8.8.8.8/udp/0/quic-v1",
      "/ip4/8.8.8.8/tcp/9000/p2p/" & $relay & "/p2p-circuit",
    ]:
      info.multiAddr = MultiAddress.init(text).get()
      pool.updatePeer(info)
      check pool.countUsable([]).get() == 0
      check info.multiAddr in pool.store[AddressBook][info.peerId]
    pool.allowAllAddresses = true
    check pool.countUsable([]).get() == 1

  test "host exclusions and recovery affect every routing query immediately":
    let pool = HostPool.new(allowAllAddresses = true)
    let info = MixNodeInfo.generateRandom(9000, rng()).toMixPubInfo()
    pool.updatePeer(info)
    pool.exclude(info.peerId)
    check pool.usablePeer(info.peerId).get().isNone
    check pool.listPeerIds().get().len == 0
    check pool.countUsable([]).get() == 0
    check pool.selectRandomNodes(1, []).isErr
    check pool.store[MixPubKeyBook][info.peerId] == info.mixPubKey
    pool.restore(info.peerId)
    check pool.selectRandomNodes(1, []).get() == @[info]

  test "a host key update survives a delete in another peer store":
    let pool = HostPool.new(allowAllAddresses = true)
    let infos = MixNodeInfo.generateRandomMany(2, rng()).mapIt(it.toMixPubInfo())
    let otherStore = PeerStore.new()
    pool.updatePeer(infos[0])
    otherStore[MixPubKeyBook][infos[0].peerId] = infos[0].mixPubKey
    var updated = infos[0]
    updated.mixPubKey = infos[1].mixPubKey
    pool.updatePeer(updated)
    otherStore.del(updated.peerId)
    check pool.usablePeer(updated.peerId).get() == Opt.some(updated)
    check pool.countUsable([]).get() == 1

  test "an incomplete host update does not restore an older mix key":
    let pool = HostPool.new(allowAllAddresses = true)
    var info = MixNodeInfo.generateRandom(9000, rng()).toMixPubInfo()
    pool.updatePeer(info)
    info.mixPubKey = default(typeof(info.mixPubKey))
    pool.updatePeer(info)
    check pool.usablePeer(info.peerId).get().isNone
    check pool.countUsable([]).get() == 0
    check pool.selectRandomNodes(1, []).isErr

  test "remove deletes the mix key and keeps the other books":
    let pool = HostPool.new(allowAllAddresses = true)
    let info = MixNodeInfo.generateRandom(9000, rng()).toMixPubInfo()
    pool.addPeer(info)
    pool.store[ProtoBook][info.peerId] = @["/other/1.0.0"]
    check pool.removePeer(info.peerId)
    check pool.usablePeer(info.peerId).get().isNone
    check pool.store[AddressBook][info.peerId] == @[info.multiAddr]
    check pool.store[KeyBook][info.peerId].skkey == info.libp2pPubKey
    check pool.store[ProtoBook][info.peerId] == @["/other/1.0.0"]

suite "MixPool contract":
  test "a pool error fails every read and selection":
    let pool = FailingPool(rng: rng())
    let info = MixNodeInfo.generateRandom(0, rng()).toMixPubInfo()
    check pool.usablePeer(info.peerId).isErr
    check pool.countUsable([]).isErr
    check pool.selectRandomNodes(1, []).isErr
    check (waitFor pool.selectReplyPeer(@[])).isErr

  test "a negative selection count returns an error":
    check newHostPool().selectRandomNodes(-1, []).isErr

  test "the default reply selection takes one usable peer that is not excluded":
    let pool = newHostPool()
    let infos = MixNodeInfo.generateRandomMany(3, rng()).mapIt(it.toMixPubInfo())
    pool.addPeers(infos)
    for _ in 0 ..< 20:
      let peer = (waitFor pool.selectReplyPeer(@[infos[0].peerId])).get()
      check peer in [infos[1].peerId, infos[2].peerId]
    check (waitFor pool.selectReplyPeer(infos.mapIt(it.peerId))).isErr

suite "MixProtocol and its pool":
  test "new keeps the pool it is given":
    let info = MixNodeInfo.generateRandom(0, rng())
    let sw = createSwitch(info.multiAddr, Opt.some(info.libp2pPrivKey))
    let pool = newHostPool()
    let mix = MixProtocol.new(info, sw, pool = pool)
    check mix.pool == MixPool(pool)

  test "new without a pool uses a stock pool on the switch peer store":
    let info = MixNodeInfo.generateRandom(0, rng())
    let sw = createSwitch(info.multiAddr, Opt.some(info.libp2pPrivKey))
    let mix = MixProtocol.new(info, sw)
    check mix.pool of MixNodePool
    let other = MixNodeInfo.generateRandom(9000, rng()).toMixPubInfo()
    MixNodePool(mix.pool).add(other)
    check sw.peerStore[MixPubKeyBook][other.peerId] == other.mixPubKey
    check mix.pool.countUsable([]).get() == 1
