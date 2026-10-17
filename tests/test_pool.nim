# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import results, sequtils, sets, tables
import
  libp2p/
    [crypto/crypto, crypto/curve25519, crypto/secp, multiaddress, peerid, peerstore]
import libp2p_mix/[mix_node, pool, mix_protocol, serialization]
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
    pool = MixNodePool.new(peerStore)
    mixNodes = MixNodeInfo.generateRandomMany(5, rng())

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

  test "get returns none when key scheme is not Secp256k1":
    let pubInfo = mixNodes[0].toMixPubInfo()

    # Manually add with wrong key scheme
    peerStore[MixPubKeyBook][pubInfo.peerId] = pubInfo.mixPubKey
    peerStore[AddressBook][pubInfo.peerId] = @[pubInfo.multiAddr]
    # KeyBook is not set, so scheme defaults to something other than Secp256k1

    check pool.get(pubInfo.peerId).isNone

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

  test "an added node uses the last outbound address, then the address book, then the added address":
    var pubInfo = mixNodes[0].toMixPubInfo()
    let addedAddr =
      MultiAddress.init("/ip4/10.0.0.1/tcp/4241").expect("could not create multiaddr")
    let bookAddr =
      MultiAddress.init("/ip4/10.0.0.2/tcp/4242").expect("could not create multiaddr")
    let lastSeenAddr =
      MultiAddress.init("/ip4/10.0.0.3/tcp/4243").expect("could not create multiaddr")
    pubInfo.multiAddr = addedAddr
    pool.add(pubInfo)
    peerStore[AddressBook][pubInfo.peerId] = @[bookAddr]
    check pool.get(pubInfo.peerId).get().multiAddr == bookAddr
    peerStore[LastSeenOutboundBook][pubInfo.peerId] = Opt.some(lastSeenAddr)
    check pool.get(pubInfo.peerId).get().multiAddr == lastSeenAddr
    peerStore.del(pubInfo.peerId)
    check pool.get(pubInfo.peerId).get().multiAddr == addedAddr

  test "an added node stays in the pool after the peer store deletes it":
    let pubInfo = mixNodes[0].toMixPubInfo()
    pool.add(pubInfo)
    peerStore.del(pubInfo.peerId)
    check:
      peerStore[MixPubKeyBook][pubInfo.peerId] == default(Curve25519Key)
      pool.len == 1
      pubInfo.peerId in pool.peerIds()
      pool.get(pubInfo.peerId) == Opt.some(pubInfo)
    check pool.remove(pubInfo.peerId)
    check:
      pool.len == 0
      pool.get(pubInfo.peerId).isNone

  test "an added node keeps the keys of its record after a later write to the books":
    let pubInfo = mixNodes[0].toMixPubInfo()
    pool.add(pubInfo)
    let other = mixNodes[1].toMixPubInfo()
    peerStore[MixPubKeyBook][pubInfo.peerId] = other.mixPubKey
    peerStore[KeyBook][pubInfo.peerId] =
      PublicKey(scheme: Secp256k1, skkey: other.libp2pPubKey)
    check pool.get(pubInfo.peerId) == Opt.some(pubInfo)

  test "an added node and a node written to the books count once each":
    let added = mixNodes[0].toMixPubInfo()
    let written = mixNodes[1].toMixPubInfo()
    pool.add(added)
    peerStore[MixPubKeyBook][written.peerId] = written.mixPubKey
    peerStore[AddressBook][written.peerId] = @[written.multiAddr]
    peerStore[KeyBook][written.peerId] =
      PublicKey(scheme: Secp256k1, skkey: written.libp2pPubKey)
    check:
      pool.len == 2
      pool.peerIds().toHashSet() == [added.peerId, written.peerId].toHashSet()
      pool.get(written.peerId) == Opt.some(written)

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

type FakePool = ref object of MixNodePool
  ## A pool that keeps its members in its own table and does not use the
  ## peer store.
  members: Table[PeerId, MixPubInfo]
  getCalls: int

method add(pool: FakePool, info: MixPubInfo) {.gcsafe, raises: [].} =
  pool.members[info.peerId] = info

method remove(pool: FakePool, peerId: PeerId): bool {.gcsafe, raises: [].} =
  let present = pool.members.hasKey(peerId)
  pool.members.del(peerId)
  present

method get(pool: FakePool, peerId: PeerId): Opt[MixPubInfo] {.gcsafe, raises: [].} =
  inc pool.getCalls
  pool.members.withValue(peerId, info):
    return Opt.some(info[])
  Opt.none(MixPubInfo)

method peerIds(pool: FakePool): seq[PeerId] {.gcsafe, raises: [].} =
  pool.members.keys.toSeq()

method len(pool: FakePool): int {.gcsafe, raises: [].} =
  pool.members.len

suite "MixNodePool subclass":
  test "buildSurb reads its hops from a subclass pool":
    let infos = MixNodeInfo.generateRandomMany(5, rng())
    let node = MixProtocol.new(
      infos[0], createSwitch(infos[0].multiAddr, Opt.some(infos[0].libp2pPrivKey))
    )
    let pool = FakePool()
    node.nodePool = pool
    # Add through the base type, so that the test finds a base `add` proc.
    for info in infos[1 .. ^1]:
      node.nodePool.add(info.toMixPubInfo())
    check node.nodePool.len == 4
    let nonMember = PeerId.random(rng()).expect("could not generate peerId")
    var id: SURBIdentifier
    rng().generate(id)
    check node.buildSurb(id, nonMember, nonMember).isOk
    check pool.getCalls == 2
    check node.switch.peerStore[MixPubKeyBook].len == 0
    check node.nodePool.remove(infos[1].peerId)
    check node.nodePool.len == 3
    check node.buildSurb(id, nonMember, nonMember).isOk
    check node.nodePool.remove(infos[2].peerId)
    check node.buildSurb(id, nonMember, nonMember).isErr
