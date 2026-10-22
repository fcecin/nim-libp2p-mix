# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Peer storage and final peer selection supplied by the host.

{.push raises: [].}

import chronos, results
import brokers/request_broker
import libp2p/[peerid, multiaddress, crypto/crypto]
import libp2p/crypto/curve25519
import ./mix_node

export broker_context, mix_node.MixPubInfo

type MixPeerRecord* = object
  ## A peer's keys and addresses approved by the host.
  ## Return an empty record for an unknown or excluded peer.
  ## Provider errors fail the whole Mix operation.
  ## List addresses in preference order.
  mixPubKey*: Curve25519Key
  publicKey*: PublicKey
  addresses*: seq[MultiAddress]

RequestBroker(sync):
  proc ReadMixPeer(peerId: PeerId): Result[MixPeerRecord, string]

RequestBroker(sync):
  proc StoreMixPeer(info: MixPubInfo): Result[void, string]

RequestBroker(sync):
  proc RemoveMixPeer(peerId: PeerId): Result[bool, string]

RequestBroker(sync):
  proc ListMixPeerIds(): Result[seq[PeerId], string]

RequestBroker:
  # Select the final peer of a reply path from the usable peers that are not
  # excluded. Mix excludes this node, the destination and the exit. A provider
  # returns soon after its request is cancelled.
  proc SelectReplyPeer(excluded: seq[PeerId]): Future[Result[PeerId, string]]

proc clearMixProviders*(ctx: BrokerContext) =
  ## Clear the five providers of `ctx`. Call it after `MixProtocol` stops.
  ReadMixPeer.clearProvider(ctx)
  StoreMixPeer.clearProvider(ctx)
  RemoveMixPeer.clearProvider(ctx)
  ListMixPeerIds.clearProvider(ctx)
  SelectReplyPeer.clearProvider(ctx)
