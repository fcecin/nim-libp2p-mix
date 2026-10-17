# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results, sequtils
import libp2p/[switch, multiaddress, peerid, dial]
import libp2p/stream/connection
import libp2p_mix
import libp2p_mix/[mix_protocol, connected_reply, serialization]
import ../utils
import ../tools/[unittest, lifecycle, crypto]

proc connectedReplyNodes(
    count: int, requireConnected = false
): Future[seq[MixProtocol]] {.async.} =
  ## `ephemeralMixNodes` where the first node ends its reply paths on a
  ## connected candidate.
  let nodes = await ephemeralMixNodes(count)
  nodes[0].replyHopPicker = connectedReplyHops(nodes[0].switch, requireConnected)
  nodes

proc recordPicks(node: MixProtocol): ref seq[PeerId] =
  ## Wraps the picker of `node` and returns the list of the hops that it picks.
  let picks = new(seq[PeerId])
  let picker = node.replyHopPicker
  node.replyHopPicker = proc(
      candidates: seq[PeerId]
  ): Result[PeerId, string] {.gcsafe, raises: [].} =
    let picked = ?picker(candidates)
    picks[].add(picked)
    ok(picked)
  picks

proc buildReplyPath(
    node: MixProtocol, destPeerId, exitPeerId: PeerId
): Result[SURB, string] =
  var id: SURBIdentifier
  rng().generate(id)
  node.buildSurb(id, destPeerId, exitPeerId)

proc makeSenderUnreachable(nodes: seq[MixProtocol]) =
  ## No node can dial the sender. Its address is on a documentation range,
  ## and the other nodes remove it from their pools.
  let sender = nodes[0]
  doAssert sender.setLocalMultiAddr(MultiAddress.init("/ip4/192.0.2.1/tcp/1").tryGet()).isOk
  for node in nodes[1 .. ^1]:
    discard node.nodePool.remove(sender.localMixPubInfo().peerId)

const ReplyParams = MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(1'u8))

suite "Connected reply hops":
  asyncTest "a sender that no node can dial receives replies for both destination kinds":
    let nodes = await connectedReplyNodes(5)
    defer:
      await stopNodes(nodes)
    nodes.makeSenderUnreachable()
    let sender = nodes[0]
    let destination = nodes[4]
    let echoProto = EchoProtocol.new()
    await echoProto.start()
    destination.switch.mount(echoProto)
    for node in nodes:
      node.registerDestReadBehavior(echoProto.codec, readLp(EchoMaxReadLen))
    let destPeerId = destination.localMixPubInfo().peerId
    check (await sender.connectReplyHop(destPeerId)).isOk
    for mode in 0 .. 1:
      let target =
        if mode == 0:
          destination.toMixDestination()
        else:
          MixDestination.exitNode(destPeerId)
      let conn = sender.toConnection(target, echoProto.codec, ReplyParams).tryGet()
      try:
        await conn.writeLp(@[1.byte, 2, 3]).wait(5.seconds)
        check (await conn.readLp(32).wait(5.seconds)) == @[1.byte, 2, 3]
        check sender.surbCredsLen == 0
      finally:
        await conn.close()
    let picks = sender.recordPicks()
    check sender.buildReplyPath(destPeerId, destPeerId).isOk
    check sender.switch.isConnected(picks[][^1])

  asyncTest "a reply returns through a random exit on three sends":
    ## The exit is a random pool member that the reply path cannot use, so one
    ## connected hop must stay available when the other one is the exit. The
    ## protocol selects a random exit for each of the three sends.
    let nodes = await connectedReplyNodes(5)
    defer:
      await stopNodes(nodes)
    nodes.makeSenderUnreachable()
    let sender = nodes[0]
    let (destNode, echoProto) = await setupDestNode(EchoProtocol.new())
    defer:
      await stopDestNode(destNode)
    for node in nodes:
      node.registerDestReadBehavior(echoProto.codec, readLp(EchoMaxReadLen))
    let destPeerId = destNode.peerInfo.peerId
    var outcomes: seq[MixHopDialOutcome]
    sender.onHopDial = proc(
        peerId: PeerId,
        addresses: seq[MultiAddress],
        outcome: MixHopDialOutcome,
        hadConnection: bool,
        error: ref CatchableError,
    ) {.gcsafe, raises: [].} =
      outcomes.add(outcome)
    check (await sender.connectReplyHop(destPeerId)).isOk
    check sender.switch.connectedPeers().len == 2
    check outcomes == @[MixHopDialOutcome.Succeeded, MixHopDialOutcome.Succeeded]
    for _ in 0 .. 2:
      let conn = sender
        .toConnection(
          MixDestination.forwardToAddr(destPeerId, destNode.peerInfo.addrs[0]),
          echoProto.codec,
          ReplyParams,
        )
        .tryGet()
      try:
        await conn.writeLp(@[4.byte, 5, 6]).wait(5.seconds)
        check (await conn.readLp(32).wait(5.seconds)) == @[4.byte, 5, 6]
      finally:
        await conn.close()
    check sender.surbCredsLen == 0

  asyncTest "the last hop falls back to a random member when none is connected":
    let nodes = await connectedReplyNodes(4)
    defer:
      await stopNodes(nodes)
    let sender = nodes[0]
    let destPeerId = nodes[3].localMixPubInfo().peerId
    check sender.switch.connectedPeers().len == 0
    let picks = sender.recordPicks()
    check sender.buildReplyPath(destPeerId, destPeerId).isOk
    check not sender.switch.isConnected(picks[][^1])

  asyncTest "the exit never ends the reply path, also when it is connected":
    let nodes = await connectedReplyNodes(5)
    defer:
      await stopNodes(nodes)
    let sender = nodes[0]
    let exitPeerId = nodes[1].localMixPubInfo().peerId
    let lastHopPeerId = nodes[2].localMixPubInfo().peerId
    let destPeerId = nodes[4].localMixPubInfo().peerId
    for node in nodes[1 .. 2]:
      await sender.switch.connect(
        node.switch.peerInfo.peerId, node.switch.peerInfo.addrs
      )
    let picks = sender.recordPicks()
    for _ in 0 ..< 20:
      check sender.buildReplyPath(destPeerId, exitPeerId).isOk
    check picks[].allIt(it == lastHopPeerId)

  asyncTest "a reply path skips a pool member with no address that the pool accepts":
    let nodes = await connectedReplyNodes(4)
    defer:
      await stopNodes(nodes)
    let sender = nodes[0]
    let destPeerId = nodes[3].localMixPubInfo().peerId
    var refused = MixNodeInfo.generateRandomMany(1, rng())[0].toMixPubInfo()
    refused.multiAddr = MultiAddress.init("/ip6/::1/tcp/4242").tryGet()
    sender.nodePool.add(refused)
    check refused.peerId in sender.nodePool.peerIds()
    let picks = sender.recordPicks()
    for _ in 0 ..< 20:
      check sender.buildReplyPath(destPeerId, destPeerId).isOk
    check picks[].allIt(it != refused.peerId)

  asyncTest "connecting a reply hop dials only the candidates that are missing":
    let nodes = await connectedReplyNodes(5)
    defer:
      await stopNodes(nodes)
    let sender = nodes[0]
    let destPeerId = nodes[4].localMixPubInfo().peerId
    let connectedPeerId = nodes[1].switch.peerInfo.peerId
    await sender.switch.connect(connectedPeerId, nodes[1].switch.peerInfo.addrs)
    var dialed: seq[PeerId]
    sender.onHopDial = proc(
        peerId: PeerId,
        addresses: seq[MultiAddress],
        outcome: MixHopDialOutcome,
        hadConnection: bool,
        error: ref CatchableError,
    ) {.gcsafe, raises: [].} =
      dialed.add(peerId)
    check (await sender.connectReplyHop(destPeerId)).isOk
    check dialed.len == 1
    check connectedPeerId notin dialed
    dialed.setLen(0)
    check (await sender.connectReplyHop(destPeerId)).isOk
    check dialed.len == 0

  asyncTest "a required connected hop fails without a connection":
    let nodes = await connectedReplyNodes(4, requireConnected = true)
    defer:
      await stopNodes(nodes)
    let sender = nodes[0]
    let destPeerId = nodes[3].localMixPubInfo().peerId
    check sender.buildReplyPath(destPeerId, destPeerId).error ==
      NoConnectedReplyHopMessage
    check (await sender.connectReplyHop(destPeerId)).isOk
    let picks = sender.recordPicks()
    check sender.buildReplyPath(destPeerId, destPeerId).isOk
    check sender.switch.isConnected(picks[][^1])
    for peerId in sender.switch.connectedPeers():
      await sender.switch.disconnect(peerId)
    check sender.buildReplyPath(destPeerId, destPeerId).error ==
      NoConnectedReplyHopMessage

  asyncTest "connecting a reply hop fails when every candidate refuses the dial":
    let nodes = await connectedReplyNodes(4)
    defer:
      await stopNodes(nodes)
    let sender = nodes[0]
    let destPeerId = nodes[3].localMixPubInfo().peerId
    for node in nodes[1 .. ^1]:
      await node.switch.stop()
    var failed = 0
    sender.onHopDial = proc(
        peerId: PeerId,
        addresses: seq[MultiAddress],
        outcome: MixHopDialOutcome,
        hadConnection: bool,
        error: ref CatchableError,
    ) {.gcsafe, raises: [].} =
      if outcome == MixHopDialOutcome.Failed and error of DialFailedError:
        failed.inc()
    check (await sender.connectReplyHop(destPeerId)).error == NoConnectedReplyHopMessage
    check sender.switch.connectedPeers().len == 0
    check failed == 2

  asyncTest "connecting a reply hop gives up at the timeout":
    ## The sender runs alone, so only the unreachable hops decide the result.
    let nodes = await connectedReplyNodes(1)
    defer:
      await stopNodes(nodes)
    let sender = nodes[0]
    let server = UnresponsiveServer.new()
    defer:
      await server.stop()
    let hops = fakeHops(4, server.address)
    sender.nodePool.add(hops)
    let destPeerId = hops[3].peerId
    var cancelled = 0
    sender.onHopDial = proc(
        peerId: PeerId,
        addresses: seq[MultiAddress],
        outcome: MixHopDialOutcome,
        hadConnection: bool,
        error: ref CatchableError,
    ) {.gcsafe, raises: [].} =
      if outcome == MixHopDialOutcome.Cancelled:
        cancelled.inc()
    let started = Moment.now()
    check (await sender.connectReplyHop(destPeerId, timeout = 200.milliseconds)).error ==
      NoConnectedReplyHopMessage
    let elapsed = Moment.now() - started
    check elapsed >= 200.milliseconds
    check elapsed < 3.seconds
    # The server can still have the second connection in its backlog at the deadline.
    check server.accepted >= 1
    check cancelled == 2
    check sender.switch.connectedPeers().len == 0
