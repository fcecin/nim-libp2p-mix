# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results, sequtils
import libp2p/[crypto/crypto, crypto/secp, multiaddress, peerid, peerstore]
import libp2p_mix/[mix_node, pool]
import ./tools/unittest
import ./tools/crypto
import ./utils

suite "MixNodePool Tests":
  var
    peerStore {.threadvar.}: PeerStore
    pool {.threadvar.}: MixNodePool
    mixNodes {.threadvar.}: seq[MixNodeInfo]

  setup:
    peerStore = PeerStore.new()
    pool = MixNodePool.new(
      peerStore, config = MixPoolConfig(addressPolicy: defaultAddressPolicy)
    )
    mixNodes = testMixNodeInfos(5)

  teardown:
    waitFor pool.stop()

  test "new creates empty pool":
    check pool.len == 0

  test "add stores mix node info":
    let pubInfo = mixNodes[0].toMixPubInfo()

    pool.add(pubInfo)

    check:
      pool.len == 1
      pool.get(pubInfo.peerId).isSome
      pool.get(pubInfo.peerId).get() == pubInfo

  test "add stores all required data in peerStore":
    let pubInfo = mixNodes[0].toMixPubInfo()

    pool.add(pubInfo)

    check:
      peerStore[MixPubKeyBook][pubInfo.peerId] == pubInfo.mixPubKey
      peerStore[AddressBook][pubInfo.peerId] == @[pubInfo.multiAddr]
      peerStore[KeyBook][pubInfo.peerId].scheme == Secp256k1
      peerStore[KeyBook][pubInfo.peerId].skkey == pubInfo.libp2pPubKey

  test "bulk add stores multiple mix nodes":
    let pubInfos = mixNodes.mapIt(it.toMixPubInfo())

    pool.add(pubInfos)

    check pool.len == mixNodes.len
    for pubInfo in pubInfos:
      check pool.get(pubInfo.peerId).isSome
      check pool.get(pubInfo.peerId).get() == pubInfo

  test "bulk add with empty seq is no-op":
    pool.add(newSeq[MixPubInfo]())
    check pool.len == 0

  test "remove deletes from pool":
    let pubInfo = mixNodes[0].toMixPubInfo()

    pool.add(pubInfo)
    check pool.len == 1

    let removed = pool.remove(pubInfo.peerId)

    check:
      removed == true
      pool.len == 0
      pool.get(pubInfo.peerId).isNone

  test "remove returns false for non-existent peer":
    let peerId = PeerId.random(rng()).expect("could not generate peerId")
    check pool.remove(peerId) == false

  test "get returns none for non-existent peer":
    let peerId = PeerId.random(rng()).expect("could not generate peerId")
    check pool.get(peerId).isNone

  test "get returns none when address is missing":
    let pubInfo = mixNodes[0].toMixPubInfo()

    # Manually add only the mix key, not the address
    peerStore[MixPubKeyBook][pubInfo.peerId] = pubInfo.mixPubKey

    check pool.get(pubInfo.peerId).isNone

  test "get extracts the public key from the peer id":
    let pubInfo = mixNodes[0].toMixPubInfo()

    # Manually add with wrong key scheme
    peerStore[MixPubKeyBook][pubInfo.peerId] = pubInfo.mixPubKey
    peerStore[AddressBook][pubInfo.peerId] = @[pubInfo.multiAddr]
    check pool.get(pubInfo.peerId).get().libp2pPubKey == pubInfo.libp2pPubKey

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
    check pool.get(pubInfo.peerId).isNone

    # Only UDP (without QUIC-v1) - should return none
    peerStore[AddressBook][pubInfo.peerId] = @[udpAddr]
    check pool.get(pubInfo.peerId).isNone

    # IPv6 and UDP first, then TCP - should return TCP
    peerStore[AddressBook][pubInfo.peerId] = @[ipv6Addr, udpAddr, tcpAddr]
    check pool.get(pubInfo.peerId).get().multiAddr == tcpAddr

    # UDP first, then QUIC-v1 - should return QUIC-v1
    peerStore[AddressBook][pubInfo.peerId] = @[udpAddr, quicAddr]
    check pool.get(pubInfo.peerId).get().multiAddr == quicAddr

    # TCP and QUIC-v1 both available - should return first match (TCP)
    peerStore[AddressBook][pubInfo.peerId] = @[tcpAddr, quicAddr]
    check pool.get(pubInfo.peerId).get().multiAddr == tcpAddr

    # TCP circuit-relay - should be supported
    peerStore[AddressBook][pubInfo.peerId] = @[tcpCircuitAddr]
    check pool.get(pubInfo.peerId).get().multiAddr == tcpCircuitAddr

    # QUIC-v1 circuit-relay - should be supported
    peerStore[AddressBook][pubInfo.peerId] = @[quicCircuitAddr]
    check pool.get(pubInfo.peerId).get().multiAddr == quicCircuitAddr

    # IPv6 circuit-relay - should return none (unsupported transport)
    peerStore[AddressBook][pubInfo.peerId] = @[ipv6CircuitAddr]
    check pool.get(pubInfo.peerId).isNone

    # Mixed: unsupported circuit-relay first, then supported - should return supported
    peerStore[AddressBook][pubInfo.peerId] = @[ipv6CircuitAddr, tcpCircuitAddr]
    check pool.get(pubInfo.peerId).get().multiAddr == tcpCircuitAddr

  test "peerIds returns all peer IDs":
    for i in 0 ..< mixNodes.len:
      let pubInfo = mixNodes[i].toMixPubInfo()
      pool.add(pubInfo)

    let peerIds = pool.peerIds()

    check peerIds.len == mixNodes.len

    for i in 0 ..< mixNodes.len:
      let pubInfo = mixNodes[i].toMixPubInfo()
      check pubInfo.peerId in peerIds

  test "len returns correct count":
    check pool.len == 0

    for i in 0 ..< 3:
      let pubInfo = mixNodes[i].toMixPubInfo()
      pool.add(pubInfo)
      check pool.len == i + 1

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
    check pool.get(pubInfo.peerId).get().multiAddr == lastSeenAddr

    # When LastSeenOutboundBook has unsupported address (IPv6), fall back to AddressBook
    peerStore[LastSeenOutboundBook][pubInfo.peerId] = Opt.some(lastSeenIpv6Addr)
    check pool.get(pubInfo.peerId).get().multiAddr == addressBookAddr

    # When LastSeenOutboundBook is empty, fall back to AddressBook
    peerStore[LastSeenOutboundBook][pubInfo.peerId] = Opt.none(MultiAddress)
    check pool.get(pubInfo.peerId).get().multiAddr == addressBookAddr

  test "multiple operations sequence":
    # Add 3 nodes
    for i in 0 ..< 3:
      let pubInfo = mixNodes[i].toMixPubInfo()
      pool.add(pubInfo)

    check pool.len == 3

    # Remove middle node
    let middlePubInfo = mixNodes[1].toMixPubInfo()
    discard pool.remove(middlePubInfo.peerId)

    check:
      pool.len == 2
      pool.get(middlePubInfo.peerId).isNone

    # Add two more nodes
    for i in 3 ..< 5:
      let pubInfo = mixNodes[i].toMixPubInfo()
      pool.add(pubInfo)

    check pool.len == 4

suite "Mix pool ownership and policy":
  asyncTest "public direct policy and encoded base both apply":
    let store = PeerStore.new()
    let pool = MixNodePool.new(store)
    defer:
      await pool.stop()
    var info = testMixNodeInfos(1)[0].toMixPubInfo()
    let peerId = info.peerId
    for address in [
      "/ip4/127.0.0.1/tcp/4000", "/ip4/10.0.0.1/tcp/4000", "/ip4/0.0.0.0/tcp/4000",
      "/ip4/8.8.8.8/tcp/0", "/ip6/::1/tcp/4000", "/ip4/8.8.8.8/udp/4000",
    ]:
      check not pool.accepts(peerId, MultiAddress.init(address).tryGet())
    check pool.accepts(peerId, MultiAddress.init("/ip4/8.8.8.8/tcp/4000").tryGet())
    let relay = MultiAddress
      .init("/ip4/8.8.8.8/tcp/4000/p2p/" & $peerId & "/p2p-circuit")
      .tryGet()
    check not pool.accepts(peerId, relay)
    pool.config.addressPolicy = proc(ma: MultiAddress): bool {.gcsafe, raises: [].} =
      ma == relay
    check not pool.accepts(peerId, relay)
    pool.config.addressPolicy = defaultAddressPolicy
    check pool.accepts(peerId, relay)
    check pool.accepts(peerId, info.multiAddr)
    check not pool.accepts(peerId, MultiAddress.init("/ip4/0.0.0.0/tcp/4000").tryGet())

  asyncTest "deletion in the peer store preserves configured and discovered nodes":
    let store = PeerStore.new()
    let pool = MixNodePool.new(
      store, config = MixPoolConfig(addressPolicy: defaultAddressPolicy)
    )
    defer:
      await pool.stop()
    let infos = testMixNodeInfos(2)
    pool.add(infos[0].toMixPubInfo())
    pool.ingest(infos[1].toMixPubInfo())
    store.del(infos[0].peerId)
    store.del(infos[1].peerId)
    check pool.len == 2
    check pool.source(infos[0].peerId).get() == MixNodeSource.Configured
    check pool.source(infos[1].peerId).get() == MixNodeSource.Discovered
    pool.maintain(Moment.now() + 2.hours)
    check pool.len == 1
    check pool.contains(infos[0].peerId)
    check not pool.contains(infos[1].peerId)

  asyncTest "discovery cap excludes self and evicts an ineligible node first":
    let infos = testMixNodeInfos(4)
    let pool = MixNodePool.new(
      PeerStore.new(),
      infos[0].peerId,
      MixPoolConfig(addressPolicy: defaultAddressPolicy, maxDiscovered: 2),
    )
    defer:
      await pool.stop()
    pool.add(infos[0].toMixPubInfo())
    check pool.knownPeerIds().len == 0
    pool.ingest(infos[1].toMixPubInfo())
    var invalid = infos[2].toMixPubInfo()
    invalid.multiAddr = MultiAddress.init("/ip6/::1/tcp/4000").tryGet()
    pool.ingest(invalid)
    pool.ingest(infos[3].toMixPubInfo())
    check pool.knownPeerIds().len == 2
    check pool.contains(infos[1].peerId)
    check not pool.contains(infos[2].peerId)
    check pool.contains(infos[3].peerId)

  asyncTest "dial evidence applies exclusions and expires without a probe":
    let store = PeerStore.new()
    let pool = MixNodePool.new(
      store, config = MixPoolConfig(addressPolicy: defaultAddressPolicy)
    )
    defer:
      await pool.stop()
    let infos = testMixNodeInfos(2)
    let info = infos[0].toMixPubInfo()
    pool.ingest(info)
    pool.add(infos[1].toMixPubInfo())
    let now = Moment.now()
    pool.reportDial(info.peerId, @[info.multiAddr], MixDialOutcome.Failed, false, false)
    check pool.len == 2
    pool.reportDial(info.peerId, @[info.multiAddr], MixDialOutcome.Failed, true, true)
    check pool.len == 2
    pool.reportDial(
      info.peerId,
      @[info.multiAddr],
      MixDialOutcome.Failed,
      false,
      true,
      connectionLimit = true,
    )
    check pool.len == 2
    pool.reportDial(
      info.peerId, @[infos[1].multiAddr], MixDialOutcome.Failed, false, true
    )
    check pool.len == 2
    let dialed = MultiAddress.init("/ip4/127.0.0.1/tcp/5000").tryGet()
    store[LastSeenOutboundBook][info.peerId] = Opt.some(dialed)
    check pool.get(info.peerId).get().multiAddr == dialed
    pool.reportDial(
      info.peerId, @[dialed], MixDialOutcome.Cancelled, false, true, now = now
    )
    check pool.get(info.peerId).isNone
    pool.maintain(now + 30.minutes)
    check pool.get(info.peerId).get().multiAddr == info.multiAddr
    store[MixPubKeyBook][info.peerId] = info.mixPubKey
    check pool.get(info.peerId).get().multiAddr == info.multiAddr
    pool.reportDial(info.peerId, @[info.multiAddr], MixDialOutcome.Failed, false, true)
    pool.reportDial(
      info.peerId, @[info.multiAddr], MixDialOutcome.Succeeded, false, true
    )
    check pool.get(info.peerId).isSome
    pool.reportDial(
      infos[1].peerId, @[infos[1].multiAddr], MixDialOutcome.Failed, false, true
    )
    check pool.get(infos[1].peerId).isSome
    check pool.counters.dialIgnored == 3
    check pool.counters.dialFailed == 3
    check pool.counters.dialSucceeded == 1

  asyncTest "book handlers detach and attach once across restarts":
    let store = PeerStore.new()
    let pool = MixNodePool.new(
      store, config = MixPoolConfig(addressPolicy: defaultAddressPolicy)
    )
    defer:
      await pool.stop()
    let info = testMixNodeInfos(1)[0].toMixPubInfo()
    var events: seq[MixPoolEventKind]
    let handler = pool.addChangeHandler(
      proc(event: MixPoolEvent) =
        events.add(event.kind)
    )
    store[AddressBook][info.peerId] = @[info.multiAddr]
    store[MixPubKeyBook][info.peerId] = info.mixPubKey
    check pool.len == 1
    check MixPoolEventKind.Owned in events
    await pool.stop()
    events.setLen(0)
    store[MixPubKeyBook][info.peerId] = info.mixPubKey
    check events.len == 0
    pool.start()
    pool.start()
    events.setLen(0)
    store[MixPubKeyBook][info.peerId] = info.mixPubKey
    check events == @[MixPoolEventKind.Updated]
    pool.removeChangeHandler(handler)
    events.setLen(0)
    discard pool.remove(info.peerId)
    check events.len == 0
