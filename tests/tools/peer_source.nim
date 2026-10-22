# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## A test host that owns a peer store. The address policy and the exclusions are
## host state.

{.push raises: [].}

import std/[sets, sequtils, tables]
import brokers/request_broker
import results
import libp2p/[peerstore, peerid, multiaddress, wire, crypto/crypto]
import ./crypto
import libp2p_mix/[peer_selection, pool, pool_providers, mix_node]

export peer_selection

type HostPeerSource* = ref object
  brokerCtx*: BrokerContext
  store*: PeerStore
  allowAllAddresses*: bool
  excluded: HashSet[PeerId]

proc accepts(source: HostPeerSource, address: MultiAddress): bool =
  if source.allowAllAddresses:
    return true
  if not (TCP_IP4.match(address) or QUIC_V1_IP4.match(address)) or
      not isPublicMA(address):
    return false
  let transport = address[1].valueOr:
    return false
  let port = transport.protoArgument().valueOr:
    return false
  port.len == 2 and (port[0] != 0 or port[1] != 0)

proc readPeer*(source: HostPeerSource, peerId: PeerId): MixPeerRecord {.gcsafe.} =
  if peerId in source.excluded:
    return MixPeerRecord()
  var record = MixPeerRecord(
    mixPubKey: source.store[MixPubKeyBook][peerId],
    publicKey: source.store[KeyBook][peerId],
  )
  for address in source.store[AddressBook][peerId]:
    if source.accepts(address):
      record.addresses.add(address)
  source.store[LastSeenOutboundBook][peerId].withValue(address):
    if source.accepts(address):
      record.addresses = @[address] & record.addresses.filterIt(it != address)
  record

proc peerIds*(source: HostPeerSource): seq[PeerId] {.gcsafe.} =
  source.store[MixPubKeyBook].book.keys.toSeq().filterIt(it notin source.excluded)

proc storePeer*(source: HostPeerSource, info: MixPubInfo) {.gcsafe.} =
  source.store[MixPubKeyBook][info.peerId] = info.mixPubKey
  let addresses = source.store[AddressBook][info.peerId]
  if info.multiAddr notin addresses:
    source.store[AddressBook].set(
      info.peerId, addresses & @[info.multiAddr], AddressConfidence.Infinite
    )
  if source.store[KeyBook][info.peerId].scheme != Secp256k1:
    source.store[KeyBook][info.peerId] =
      PublicKey(scheme: Secp256k1, skkey: info.libp2pPubKey)
  source.excluded.excl(info.peerId)

proc removePeer*(source: HostPeerSource, peerId: PeerId): bool {.gcsafe.} =
  source.excluded.excl(peerId)
  source.store[MixPubKeyBook].del(peerId)

proc updatePeer*(source: HostPeerSource, info: MixPubInfo) =
  ## Replace the peer keys and addresses with the latest discovery result.
  source.store[MixPubKeyBook][info.peerId] = info.mixPubKey
  source.store[KeyBook][info.peerId] =
    PublicKey(scheme: Secp256k1, skkey: info.libp2pPubKey)
  source.store[AddressBook].set(
    info.peerId, @[info.multiAddr], AddressConfidence.Infinite
  )

proc exclude*(source: HostPeerSource, peerId: PeerId) =
  source.excluded.incl(peerId)

proc restore*(source: HostPeerSource, peerId: PeerId) =
  source.excluded.excl(peerId)

RequestBroker(sync):
  proc GetHostPeerSource(): Result[HostPeerSource, string]

var testContexts {.threadvar.}: seq[BrokerContext]

proc clearHostPeerProviders*() =
  for ctx in testContexts:
    ReadMixPeer.clearProvider(ctx)
    StoreMixPeer.clearProvider(ctx)
    RemoveMixPeer.clearProvider(ctx)
    ListMixPeerIds.clearProvider(ctx)
    SelectReplyPeer.clearProvider(ctx)
    GetHostPeerSource.clearProvider(ctx)
  testContexts.setLen(0)

proc new*(
    T: typedesc[HostPeerSource],
    allowAllAddresses = false,
    store: PeerStore = nil,
    brokerCtx: BrokerContext = NewBrokerContext(),
): T =
  let source = T(
    brokerCtx: brokerCtx,
    store: (if store.isNil: PeerStore.new() else: store),
    allowAllAddresses: allowAllAddresses,
  )
  let ctx = source.brokerCtx
  testContexts.add(ctx)
  ReadMixPeer
    .setProvider(
      ctx,
      proc(peerId: PeerId): Result[MixPeerRecord, string] =
        ok(source.readPeer(peerId)),
    )
    .expect("register read provider")
  StoreMixPeer
    .setProvider(
      ctx,
      proc(info: MixPubInfo): Result[void, string] =
        source.storePeer(info)
        ok(),
    )
    .expect("register store provider")
  RemoveMixPeer
    .setProvider(
      ctx,
      proc(peerId: PeerId): Result[bool, string] =
        ok(source.removePeer(peerId)),
    )
    .expect("register remove provider")
  ListMixPeerIds
    .setProvider(
      ctx,
      proc(): Result[seq[PeerId], string] =
        ok(source.peerIds()),
    )
    .expect("register ID provider")
  GetHostPeerSource
    .setProvider(
      ctx,
      proc(): Result[HostPeerSource, string] =
        ok(source),
    )
    .expect("register test store provider")
  registerRandomReplySelection(ctx, rng()).expect("register test peer providers")
  source

proc testPeerSource*(ctx: BrokerContext): HostPeerSource =
  GetHostPeerSource.request(ctx).expect("test peer store")

proc hostPeerContext*(): BrokerContext =
  ## A context whose host store accepts every address.
  HostPeerSource.new(allowAllAddresses = true).brokerCtx

proc poolPeerContext*(store: PeerStore = nil): BrokerContext =
  ## A context with the standalone `MixNodePool` providers.
  let ctx = NewBrokerContext()
  testContexts.add(ctx)
  registerMixPeerProviders(ctx, (if store.isNil: PeerStore.new() else: store)).expect(
    "register test peer providers"
  )
  registerRandomReplySelection(ctx, rng()).expect("register test peer providers")
  ctx
