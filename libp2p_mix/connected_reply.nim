# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Connected Reply Paths
##
## An optional protocol subclass that ends each reply path on a pool member
## with a connection to this node. A reply then goes through that connection
## to this node, and no other node has to dial this node. So a sender behind
## NAT receives its replies. A candidate is a pool member that can be on the
## reply path. The exit, the destination and this node are not candidates.
## When no candidate has a connection, the path ends on a random candidate,
## unless `requireConnectedHop` is set.
## The first hops of this node stay connected, so the first hop of a request
## can end the path of its reply. That node already knows this node.
##
## Before a request that expects a reply, an application can call
## `connectReplyHop`. It dials candidates that are not connected and returns
## when the dials end or when `prepareTimeout` passes. The exit of the request
## is one pool member that the reply path cannot use, so the default
## `prepareDialCount` is 2.

{.push raises: [].}

import std/sequtils
import chronos, metrics, results
import libp2p/[switch, peerid, multiaddress, dial, peeraddrpolicy]
import libp2p/crypto/crypto
import
  ./[
    mix_protocol, mix_node, pool, sphinx, serialization, delay, delay_strategy,
    curve25519, mix_metrics, tag_manager, spam_protection, cover_traffic, surb_store,
    multiaddr,
  ]

export mix_protocol

const NoConnectedReplyHopMessage* =
  "no mix node in the pool has a connection for the reply"

type
  ConnectedReplyConfig* = object
    requireConnectedHop*: bool = false
      ## When true, `buildSurb` fails if no reply path candidate has a connection
      ## to this node.
    prepareDialCount*: int = 2
      ## How many connected candidates `connectReplyHop` wants. The exit of a
      ## request to a `ForwardAddr` destination is one pool member that the
      ## reply path cannot use, so such a request needs at least 2. A request
      ## to a `MixNode` destination, where the exit is the destination, needs 1.
    prepareTimeout*: Duration = 5.seconds
      ## How long `connectReplyHop` waits for the dials.

  ConnectedReplyMixProtocol* = ref object of MixProtocol
    replyConfig: ConnectedReplyConfig

proc init*(
    mixProto: ConnectedReplyMixProtocol,
    mixNodeInfo: MixNodeInfo,
    switch: Switch,
    replyConfig = ConnectedReplyConfig(),
    tagManager: TagManager = TagManager.new(),
    spamProtection: Opt[SpamProtection] = default(Opt[SpamProtection]),
    delayStrategy: Opt[DelayStrategy] = Opt.none(DelayStrategy),
    coverTraffic: Opt[CoverTraffic] = Opt.none(CoverTraffic),
    surbStore: SurbStore = nil,
    addressPolicy: PeerAddressPolicy = defaultAddressPolicy,
) =
  ## Initialize the protocol, for a subclass that builds its own object. The
  ## other parameters are those of `MixProtocol.init`.
  doAssert replyConfig.prepareDialCount >= 1, "prepareDialCount must be positive"
  doAssert replyConfig.prepareTimeout > ZeroDuration, "prepareTimeout must be positive"
  MixProtocol(mixProto).init(
    mixNodeInfo, switch, tagManager, spamProtection, delayStrategy, coverTraffic,
    surbStore, addressPolicy,
  )
  mixProto.replyConfig = replyConfig

proc new*(
    T: typedesc[ConnectedReplyMixProtocol],
    mixNodeInfo: MixNodeInfo,
    switch: Switch,
    replyConfig = ConnectedReplyConfig(),
    tagManager: TagManager = TagManager.new(),
    spamProtection: Opt[SpamProtection] = default(Opt[SpamProtection]),
    delayStrategy: Opt[DelayStrategy] = Opt.none(DelayStrategy),
    coverTraffic: Opt[CoverTraffic] = Opt.none(CoverTraffic),
    surbStore: SurbStore = nil,
    addressPolicy: PeerAddressPolicy = defaultAddressPolicy,
): T =
  ## Create the protocol. The other parameters are those of `MixProtocol.new`.
  let mixProto = new(T)
  mixProto.init(
    mixNodeInfo, switch, replyConfig, tagManager, spamProtection, delayStrategy,
    coverTraffic, surbStore, addressPolicy,
  )
  mixProto

func replyConfig*(mixProto: ConnectedReplyMixProtocol): ConnectedReplyConfig =
  mixProto.replyConfig

proc replyCandidates(
    mixProto: ConnectedReplyMixProtocol, destPeerId, exitPeerId: PeerId
): seq[PeerId] =
  ## The pool members that can be on a reply path. A member that `get` refuses,
  ## for example by the address policy, is not a candidate.
  let selfId = mixProto.switch.peerInfo.peerId
  mixProto.nodePool.peerIds().filterIt(
    it != destPeerId and it != exitPeerId and it != selfId and
      mixProto.nodePool.get(it).isSome()
  )

proc replyPath*(
    mixProto: ConnectedReplyMixProtocol, destPeerId, exitPeerId: PeerId
): Result[seq[MixPubInfo], string] =
  ## The hops of a reply path, from the first intermediate hop to this node.
  ## The hop before this node is a candidate with a connection to this node,
  ## when such a candidate exists.
  let candidates = mixProto.replyCandidates(destPeerId, exitPeerId)
  if candidates.len < PathLength - 1:
    return err("not enough mix nodes for a reply path")
  let connected = candidates.filterIt(mixProto.switch.isConnected(it))
  let last =
    if connected.len > 0:
      mixProto.switch.rng.pickOne(connected).get()
    elif mixProto.replyConfig.requireConnectedHop:
      return err(NoConnectedReplyHopMessage)
    else:
      mixProto.switch.rng.pickOne(candidates).get()
  let preceding = mixProto.switch.rng.pick(
    candidates.filterIt(it != last), PathLength - 2
  ).valueOr:
    return err("not enough mix nodes for a reply path")
  var path: seq[MixPubInfo]
  for peerId in preceding & @[last]:
    let info = mixProto.nodePool.get(peerId).valueOr:
      return err("reply hop left the pool")
    path.add(info)
  path.add(mixProto.localMixPubInfo())
  ok(path)

method buildSurb*(
    mixProto: ConnectedReplyMixProtocol,
    id: SURBIdentifier,
    destPeerId: PeerId,
    exitPeerId: PeerId,
): Result[SURB, string] {.gcsafe, raises: [].} =
  let path = ?mixProto.replyPath(destPeerId, exitPeerId)
  var
    publicKeys: seq[FieldElement]
    hops: seq[Hop]
    delays: seq[Delay]
  for i, node in path:
    let encoded = multiAddrToBytes(node.peerId, node.multiAddr).valueOr:
      mix_messages_error.inc(labelValues = ["Entry/SURB", "INVALID_MIX_INFO"])
      return err("failed to encode reply hop: " & error)
    publicKeys.add(node.mixPubKey)
    hops.add(Hop.init(encoded))
    delays.add(
      if i < path.len - 1:
        mixProto.delayStrategy.generateForEntry()
      else:
        NoDelay
    )
  createSURB(publicKeys, delays, hops, id, mixProto.switch.rng)

proc dialHop(
    mixProto: ConnectedReplyMixProtocol, peerId: PeerId, address: MultiAddress
) {.async: (raises: [CancelledError]).} =
  ## Dials one candidate and reports the outcome to `onHopDial`. The proc
  ## returns no error, because `connectReplyHop` reads the connection state
  ## of each candidate after the dials.
  let hadConnection = mixProto.switch.isConnected(peerId)
  var outcome = MixHopDialOutcome.Succeeded
  var error: ref CatchableError
  try:
    await mixProto.switch.connect(peerId, @[address])
  except DialFailedError as exc:
    outcome = MixHopDialOutcome.Failed
    error = exc
  except CancelledError as exc:
    if not mixProto.onHopDial.isNil:
      mixProto.onHopDial(
        peerId, @[address], MixHopDialOutcome.Cancelled, hadConnection, nil
      )
    raise exc
  if not mixProto.onHopDial.isNil:
    mixProto.onHopDial(peerId, @[address], outcome, hadConnection, error)

proc connectReplyHop*(
    mixProto: ConnectedReplyMixProtocol, destPeerId: PeerId
): Future[Result[void, string]] {.async: (raises: [CancelledError]).} =
  ## Connect to reply path candidates before a request to `destPeerId`.
  ## Returns immediately when at least `prepareDialCount` candidates are
  ## connected. Otherwise dials enough candidates that are not connected to
  ## reach that count, and returns when the dials end or `prepareTimeout`
  ## passes. Returns ok when at least one candidate is connected, and an error
  ## when none is or when the pool has too few candidates for a reply path.
  let candidates = mixProto.replyCandidates(destPeerId, destPeerId)
  if candidates.len < PathLength - 1:
    return err("not enough mix nodes for a reply path")
  let connected = candidates.filterIt(mixProto.switch.isConnected(it))
  let missing = mixProto.replyConfig.prepareDialCount - connected.len
  if missing <= 0:
    return ok()
  let unconnected = candidates.filterIt(not mixProto.switch.isConnected(it))
  let chosen = mixProto.switch.rng.pick(unconnected, missing).valueOr:
    return ok()
  var pending: seq[Future[void].Raising([CancelledError])]
  for peerId in chosen:
    let info = mixProto.nodePool.get(peerId).valueOr:
      continue
    pending.add(mixProto.dialHop(peerId, info.multiAddr))
  if pending.len > 0:
    let deadline = sleepAsync(mixProto.replyConfig.prepareTimeout)
    try:
      discard await race(FutureBase(deadline), @[FutureBase(allFutures(pending))])
    finally:
      await noCancel allFutures(
        pending.mapIt(it.cancelAndWait()) & @[deadline.cancelAndWait()]
      )
  if mixProto.replyCandidates(destPeerId, destPeerId).anyIt(
    mixProto.switch.isConnected(it)
  ):
    return ok()
  err(NoConnectedReplyHopMessage)
