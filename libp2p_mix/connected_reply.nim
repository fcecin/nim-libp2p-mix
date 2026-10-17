# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Connected Reply Hops
##
## An optional reply hop picker and a preparation dial, so a sender behind NAT
## (a node that no other node can dial) receives its replies. The picker of
## `connectedReplyHops` ends each reply path on a candidate with a connection
## to this node. A reply then goes through that connection, and no other node
## has to dial this node. When no candidate has a connection, the picker draws
## one at random, unless `requireConnected` is set. The first hops of this node
## stay connected, so the first hop of a request can end the path of its
## reply. That node already knows this node.
##
## Before a request that expects a reply, an application can call
## `connectReplyHop`. It dials candidates that are not connected and returns
## when the dials end or when the timeout passes. The exit of a request to a
## `ForwardAddr` destination is one pool member that the reply path cannot
## use, so the default count is 2.

{.push raises: [].}

import std/sequtils
import chronos, results
import libp2p/[switch, peerid, multiaddress, dial]
import libp2p/crypto/crypto
import ./[mix_protocol, mix_node, pool, sphinx]

export mix_protocol

const NoConnectedReplyHopMessage* =
  "no mix node in the pool has a connection for the reply"

proc connectedReplyHops*(switch: Switch, requireConnected = false): MixReplyHopPicker =
  ## Returns a reply hop picker that prefers a candidate with a connection to
  ## this node. Without one, it draws a random candidate, or it fails with
  ## `NoConnectedReplyHopMessage` when `requireConnected` is set.
  return proc(candidates: seq[PeerId]): Result[PeerId, string] {.gcsafe, raises: [].} =
    let connected = candidates.filterIt(switch.isConnected(it))
    if connected.len > 0:
      return ok(switch.rng.pickOne(connected).get())
    if requireConnected:
      return err(NoConnectedReplyHopMessage)
    let picked = switch.rng.pickOne(candidates).valueOr:
      return err("not enough mix nodes for a reply path")
    ok(picked)

proc replyCandidates(mixProto: MixProtocol, destPeerId: PeerId): seq[PeerId] =
  ## The pool members that can end a reply path of a request to `destPeerId`.
  let selfId = mixProto.switch.peerInfo.peerId
  mixProto.nodePool.peerIds().filterIt(
    it != destPeerId and it != selfId and mixProto.nodePool.get(it).isSome()
  )

proc dialHop(
    mixProto: MixProtocol, peerId: PeerId, address: MultiAddress
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
    mixProto: MixProtocol, destPeerId: PeerId, dialCount = 2, timeout = 5.seconds
): Future[Result[void, string]] {.async: (raises: [CancelledError]).} =
  ## Connects this node to reply path candidates before a request to
  ## `destPeerId`. Returns immediately when at least `dialCount` candidates are
  ## connected. Otherwise dials enough candidates that are not connected to
  ## reach that count, and returns when the dials end or `timeout` passes.
  ## Returns ok when at least one candidate is connected, and an error when
  ## none is or when the pool has too few candidates for a reply path.
  doAssert dialCount >= 1, "dialCount must be positive"
  let candidates = mixProto.replyCandidates(destPeerId)
  if candidates.len < PathLength - 1:
    return err("not enough mix nodes for a reply path")
  let connected = candidates.filterIt(mixProto.switch.isConnected(it))
  let missing = dialCount - connected.len
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
    let deadline = sleepAsync(timeout)
    try:
      discard await race(FutureBase(deadline), @[FutureBase(allFutures(pending))])
    finally:
      await noCancel allFutures(
        pending.mapIt(it.cancelAndWait()) & @[deadline.cancelAndWait()]
      )
  if mixProto.replyCandidates(destPeerId).anyIt(mixProto.switch.isConnected(it)):
    return ok()
  err(NoConnectedReplyHopMessage)
