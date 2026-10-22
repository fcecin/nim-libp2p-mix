# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import results, sequtils
import libp2p/[crypto/crypto, crypto/secp, multiaddress, peerid, peerstore]
import libp2p_mix/[mix_node, pool, peer_selection, pool_providers, mix_protocol]
import ./tools/[unittest, peer_source]
import ./tools/crypto
import ./utils

suite "Host peer storage":
  var
    peerStore {.threadvar.}: PeerStore
    ctx {.threadvar.}: BrokerContext
    mixNodes {.threadvar.}: seq[MixNodeInfo]

  setup:
    peerStore = PeerStore.new()
    ctx = HostPeerSource.new(allowAllAddresses = true, store = peerStore).brokerCtx
    mixNodes = MixNodeInfo.generateRandomMany(5, rng())

  test "new creates an empty store":
    check ctx.peerIds().get().len == 0

  test "add stores mix node info":
    let pubInfo = mixNodes[0].toMixPubInfo()

    ctx.add(pubInfo).get()

    check:
      ctx.peerIds().get().len == 1
      ctx.get(pubInfo.peerId).get().isSome
      ctx.get(pubInfo.peerId).get().get() == pubInfo

  test "add stores all required data in peerStore":
    let pubInfo = mixNodes[0].toMixPubInfo()

    ctx.add(pubInfo).get()

    check:
      peerStore[MixPubKeyBook][pubInfo.peerId] == pubInfo.mixPubKey
      peerStore[AddressBook][pubInfo.peerId] == @[pubInfo.multiAddr]
      peerStore[KeyBook][pubInfo.peerId].scheme == Secp256k1
      peerStore[KeyBook][pubInfo.peerId].skkey == pubInfo.libp2pPubKey

  test "bulk add stores multiple mix nodes":
    let pubInfos = mixNodes.mapIt(it.toMixPubInfo())

    ctx.add(pubInfos).get()

    check ctx.peerIds().get().len == mixNodes.len
    for pubInfo in pubInfos:
      check ctx.get(pubInfo.peerId).get().isSome
      check ctx.get(pubInfo.peerId).get().get() == pubInfo

  test "bulk add with empty seq is no-op":
    ctx.add(newSeq[MixPubInfo]()).get()
    check ctx.peerIds().get().len == 0

  test "remove deletes from the store":
    let pubInfo = mixNodes[0].toMixPubInfo()

    ctx.add(pubInfo).get()
    check ctx.peerIds().get().len == 1

    let removed = ctx.remove(pubInfo.peerId).get()

    check:
      removed == true
      ctx.peerIds().get().len == 0
      ctx.get(pubInfo.peerId).get().isNone

  test "remove returns false for non-existent peer":
    let peerId = PeerId.random(rng()).expect("could not generate peerId")
    check ctx.remove(peerId).get() == false

  test "get returns none for non-existent peer":
    let peerId = PeerId.random(rng()).expect("could not generate peerId")
    check ctx.get(peerId).get().isNone

  test "get returns none when address is missing":
    let pubInfo = mixNodes[0].toMixPubInfo()

    # Manually add only the mix key, not the address
    peerStore[MixPubKeyBook][pubInfo.peerId] = pubInfo.mixPubKey

    check ctx.get(pubInfo.peerId).get().isNone

  test "get returns none when key scheme is not Secp256k1":
    let pubInfo = mixNodes[0].toMixPubInfo()

    # Manually add with wrong key scheme
    peerStore[MixPubKeyBook][pubInfo.peerId] = pubInfo.mixPubKey
    peerStore[AddressBook][pubInfo.peerId] = @[pubInfo.multiAddr]
    # KeyBook is not set, so scheme defaults to something other than Secp256k1

    check ctx.get(pubInfo.peerId).get().isNone

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
    check ctx.get(pubInfo.peerId).get().isNone

    # Only UDP (without QUIC-v1) - should return none
    peerStore[AddressBook][pubInfo.peerId] = @[udpAddr]
    check ctx.get(pubInfo.peerId).get().isNone

    # IPv6 and UDP first, then TCP - should return TCP
    peerStore[AddressBook][pubInfo.peerId] = @[ipv6Addr, udpAddr, tcpAddr]
    check ctx.get(pubInfo.peerId).get().get().multiAddr == tcpAddr

    # UDP first, then QUIC-v1 - should return QUIC-v1
    peerStore[AddressBook][pubInfo.peerId] = @[udpAddr, quicAddr]
    check ctx.get(pubInfo.peerId).get().get().multiAddr == quicAddr

    # TCP and QUIC-v1 both available - should return first match (TCP)
    peerStore[AddressBook][pubInfo.peerId] = @[tcpAddr, quicAddr]
    check ctx.get(pubInfo.peerId).get().get().multiAddr == tcpAddr

    # TCP circuit-relay - should be supported
    peerStore[AddressBook][pubInfo.peerId] = @[tcpCircuitAddr]
    check ctx.get(pubInfo.peerId).get().get().multiAddr == tcpCircuitAddr

    # QUIC-v1 circuit-relay - should be supported
    peerStore[AddressBook][pubInfo.peerId] = @[quicCircuitAddr]
    check ctx.get(pubInfo.peerId).get().get().multiAddr == quicCircuitAddr

    # IPv6 circuit-relay - should return none (unsupported transport)
    peerStore[AddressBook][pubInfo.peerId] = @[ipv6CircuitAddr]
    check ctx.get(pubInfo.peerId).get().isNone

    # Mixed: unsupported circuit-relay first, then supported - should return supported
    peerStore[AddressBook][pubInfo.peerId] = @[ipv6CircuitAddr, tcpCircuitAddr]
    check ctx.get(pubInfo.peerId).get().get().multiAddr == tcpCircuitAddr

  test "peerIds returns all peer IDs":
    for i in 0 ..< mixNodes.len:
      let pubInfo = mixNodes[i].toMixPubInfo()
      ctx.add(pubInfo).get()

    let peerIds = ctx.peerIds().get()

    check peerIds.len == mixNodes.len

    for i in 0 ..< mixNodes.len:
      let pubInfo = mixNodes[i].toMixPubInfo()
      check pubInfo.peerId in peerIds

  test "duplicate host IDs count once and never repeat a hop":
    let first = mixNodes[0].toMixPubInfo()
    let second = mixNodes[1].toMixPubInfo()
    ctx.add(@[first, second]).get()
    ListMixPeerIds
      .replaceProvider(
        ctx,
        proc(): Result[seq[PeerId], string] =
          ok(@[first.peerId, first.peerId, second.peerId, first.peerId]),
      )
      .get()
    check ctx.count([]).get() == 2
    check ctx.selectRandomNodes(rng(), 3, []).isErr
    for _ in 0 ..< 30:
      let selected = ctx.selectRandomNodes(rng(), 2, []).get()
      check selected[0].peerId != selected[1].peerId

  test "peerIds counts the stored peers":
    check ctx.peerIds().get().len == 0

    for i in 0 ..< 3:
      let pubInfo = mixNodes[i].toMixPubInfo()
      ctx.add(pubInfo).get()
      check ctx.peerIds().get().len == i + 1

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
    check ctx.get(pubInfo.peerId).get().get().multiAddr == lastSeenAddr

    # When LastSeenOutboundBook has unsupported address (IPv6), fall back to AddressBook
    peerStore[LastSeenOutboundBook][pubInfo.peerId] = Opt.some(lastSeenIpv6Addr)
    check ctx.get(pubInfo.peerId).get().get().multiAddr == addressBookAddr

    # When LastSeenOutboundBook is empty, fall back to AddressBook
    peerStore[LastSeenOutboundBook][pubInfo.peerId] = Opt.none(MultiAddress)
    check ctx.get(pubInfo.peerId).get().get().multiAddr == addressBookAddr

  test "multiple operations sequence":
    # Add 3 nodes
    for i in 0 ..< 3:
      let pubInfo = mixNodes[i].toMixPubInfo()
      ctx.add(pubInfo).get()

    check ctx.peerIds().get().len == 3

    # Remove middle node
    let middlePubInfo = mixNodes[1].toMixPubInfo()
    discard ctx.remove(middlePubInfo.peerId).get()

    check:
      ctx.peerIds().get().len == 2
      ctx.get(middlePubInfo.peerId).get().isNone

    # Add two more nodes
    for i in 3 ..< 5:
      let pubInfo = mixNodes[i].toMixPubInfo()
      ctx.add(pubInfo).get()

    check ctx.peerIds().get().len == 4

suite "Host-owned routing view":
  test "the host changes its address policy with no new store or library option":
    let source = HostPeerSource.new()
    let ctx = source.brokerCtx
    let info = MixNodeInfo.generateRandom(9000, rng()).toMixPubInfo()
    ctx.add(info).get()
    check source.store[AddressBook][info.peerId] == @[info.multiAddr]
    check ctx.get(info.peerId).get().isNone
    check ctx.count([]).get() == 0
    source.allowAllAddresses = true
    check ctx.get(info.peerId).get() == Opt.some(info)
    check ctx.count([]).get() == 1
    source.allowAllAddresses = false
    check ctx.count([]).get() == 0

  test "host-approved outbound and fallback addresses follow one rule":
    let source = HostPeerSource.new()
    let ctx = source.brokerCtx
    var info = MixNodeInfo.generateRandom(9000, rng()).toMixPubInfo()
    info.multiAddr = MultiAddress.init("/ip4/8.8.8.8/tcp/9000").get()
    ctx.add(info).get()
    source.store[LastSeenOutboundBook][info.peerId] =
      Opt.some(MultiAddress.init("/ip4/127.0.0.1/tcp/9001").get())
    check ctx.get(info.peerId).get().get().multiAddr == info.multiAddr
    let publicQuic = MultiAddress.init("/ip4/8.8.4.4/udp/9001/quic-v1").get()
    source.store[LastSeenOutboundBook][info.peerId] = Opt.some(publicQuic)
    check ctx.get(info.peerId).get().get().multiAddr == publicQuic

  test "strict filtering belongs to the host and preserves rejected source data":
    let source = HostPeerSource.new()
    let ctx = source.brokerCtx
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
      source.updatePeer(info)
      check ctx.count([]).get() == 0
      check info.multiAddr in source.store[AddressBook][info.peerId]
    source.allowAllAddresses = true
    check ctx.count([]).get() == 1

  test "host exclusions and recovery affect every routing query immediately":
    let source = HostPeerSource.new(allowAllAddresses = true)
    let ctx = source.brokerCtx
    let info = MixNodeInfo.generateRandom(9000, rng()).toMixPubInfo()
    source.updatePeer(info)
    source.exclude(info.peerId)
    check ctx.get(info.peerId).get().isNone
    check ctx.peerIds().get().len == 0
    check ctx.count([]).get() == 0
    check ctx.selectRandomNodes(rng(), 1, []).isErr
    check source.store[MixPubKeyBook][info.peerId] == info.mixPubKey
    source.restore(info.peerId)
    check ctx.selectRandomNodes(rng(), 1, []).get() == @[info]

  test "a host key update survives a delete in another peer store":
    let source = HostPeerSource.new(allowAllAddresses = true)
    let ctx = source.brokerCtx
    let infos = MixNodeInfo.generateRandomMany(2, rng()).mapIt(it.toMixPubInfo())
    let otherStore = PeerStore.new()
    source.updatePeer(infos[0])
    otherStore[MixPubKeyBook][infos[0].peerId] = infos[0].mixPubKey
    var updated = infos[0]
    updated.mixPubKey = infos[1].mixPubKey
    source.updatePeer(updated)
    otherStore.del(updated.peerId)
    check ctx.get(updated.peerId).get() == Opt.some(updated)
    check ctx.count([]).get() == 1

  test "an incomplete host update does not restore an older mix key":
    let source = HostPeerSource.new(allowAllAddresses = true)
    let ctx = source.brokerCtx
    var info = MixNodeInfo.generateRandom(9000, rng()).toMixPubInfo()
    source.updatePeer(info)
    info.mixPubKey = default(typeof(info.mixPubKey))
    source.updatePeer(info)
    check ctx.get(info.peerId).get().isNone
    check ctx.count([]).get() == 0
    check ctx.selectRandomNodes(rng(), 1, []).isErr

  test "remove deletes the mix key and keeps the other books":
    let source = HostPeerSource.new(allowAllAddresses = true)
    let ctx = source.brokerCtx
    let info = MixNodeInfo.generateRandom(9000, rng()).toMixPubInfo()
    ctx.add(info).get()
    source.store[ProtoBook][info.peerId] = @["/other/1.0.0"]
    check ctx.remove(info.peerId).get()
    check ctx.get(info.peerId).get().isNone
    check source.store[AddressBook][info.peerId] == @[info.multiAddr]
    check source.store[KeyBook][info.peerId].skkey == info.libp2pPubKey
    check source.store[ProtoBook][info.peerId] == @["/other/1.0.0"]

suite "Peer broker contract":
  test "separate contexts keep peer reads and updates isolated":
    let first = HostPeerSource.new(allowAllAddresses = true)
    let second = HostPeerSource.new(allowAllAddresses = true)
    let firstCtx = first.brokerCtx
    let secondCtx = second.brokerCtx
    let info = MixNodeInfo.generateRandom(0, rng()).toMixPubInfo()
    firstCtx.add(info).get()
    check:
      first.brokerCtx != second.brokerCtx
      firstCtx.get(info.peerId).get().isSome
      secondCtx.get(info.peerId).get().isNone
    secondCtx.add(info).get()
    check firstCtx.remove(info.peerId).get()
    check secondCtx.get(info.peerId).get().get() == info
    ReadMixPeer.clearProvider(first.brokerCtx)
    check:
      ReadMixPeer.request(first.brokerCtx, info.peerId).isErr
      secondCtx.get(info.peerId).get().get() == info
    check firstCtx.get(info.peerId).isErr

  test "the default context works when its providers are registered":
    let source =
      HostPeerSource.new(allowAllAddresses = true, brokerCtx = DefaultBrokerContext)
    let ctx = source.brokerCtx
    let info = MixNodeInfo.generateRandom(0, rng()).toMixPubInfo()
    ctx.add(info).get()
    check:
      ctx == DefaultBrokerContext
      ctx.get(info.peerId).get().get() == info
      ctx.remove(info.peerId).get()
      ctx.get(info.peerId).get().isNone

  test "unavailable providers return errors":
    let ctx = NewBrokerContext()
    let info = MixNodeInfo.generateRandom(0, rng()).toMixPubInfo()
    check ctx.get(info.peerId).isErr
    check ctx.add(info).isErr
    check ctx.remove(info.peerId).isErr
    check ctx.peerIds().isErr
    check ctx.count([]).isErr
    check ctx.selectRandomNodes(rng(), 1, []).isErr

  test "a provider error fails every read and update":
    let source = HostPeerSource.new(allowAllAddresses = true)
    let ctx = source.brokerCtx
    let info = MixNodeInfo.generateRandom(0, rng()).toMixPubInfo()
    ReadMixPeer
      .replaceProvider(
        source.brokerCtx,
        proc(peerId: PeerId): Result[MixPeerRecord, string] =
          err("read failed"),
      )
      .expect("replace read provider")
    StoreMixPeer
      .replaceProvider(
        source.brokerCtx,
        proc(info: MixPubInfo): Result[void, string] =
          err("store failed"),
      )
      .expect("replace store provider")
    RemoveMixPeer
      .replaceProvider(
        source.brokerCtx,
        proc(peerId: PeerId): Result[bool, string] =
          err("remove failed"),
      )
      .expect("replace remove provider")
    ListMixPeerIds
      .replaceProvider(
        source.brokerCtx,
        proc(): Result[seq[PeerId], string] =
          err("list failed"),
      )
      .expect("replace ID provider")
    check ctx.get(info.peerId).isErr
    check ctx.add(info).isErr
    check ctx.remove(info.peerId).isErr
    check ctx.peerIds().isErr

suite "MixProtocol peer contract":
  test "new stores the context and checks no provider":
    let ctx = NewBrokerContext()
    let info = MixNodeInfo.generateRandom(0, rng())
    let sw = createSwitch(info.multiAddr, Opt.some(info.libp2pPrivKey))
    let mix = MixProtocol.new(info, sw, brokerCtx = ctx)
    check mix.brokerCtx == ctx
    check mix.brokerCtx.count([]).isErr

  test "registration errors return through Result":
    let ctx = poolPeerContext()
    check registerMixPeerProviders(ctx, PeerStore.new()).isErr
    check registerRandomReplySelection(ctx, rng()).isErr

  test "a negative selection count returns an error":
    check NewBrokerContext().selectRandomNodes(rng(), -1, []).isErr

  test "failed standalone registration rolls back only its own providers":
    let ctx = NewBrokerContext()
    defer:
      clearMixProviders(ctx)
    StoreMixPeer
      .setProvider(
        ctx,
        proc(info: MixPubInfo): Result[void, string] =
          ok(),
      )
      .get()
    check registerMixPeerProviders(ctx, PeerStore.new()).isErr
    check not ReadMixPeer.isProvided(ctx)
    check StoreMixPeer.isProvided(ctx)
    check not RemoveMixPeer.isProvided(ctx)
    check not ListMixPeerIds.isProvided(ctx)
    StoreMixPeer.clearProvider(ctx)
    check registerMixPeerProviders(ctx, PeerStore.new()).isOk
