# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results, stew/byteutils, sequtils, tables
import
  libp2p/[
    protocols/ping,
    peerid,
    peerstore,
    multiaddress,
    switch,
    builders,
    crypto/crypto,
    crypto/secp,
  ]
import libp2p_mix
import libp2p_mix/mix_protocol
import libp2p_mix/sphinx
import libp2p_mix/delay_strategy

import ../tools/[lifecycle, unittest, crypto]
import ../utils
import ../mock_mix

suite "Mix Protocol - Node Failures":
  asyncTeardown:
    checkTrackers()

  asyncTest "multiple SURBs - reply received when one path unavailable":
    ## 2 SURBs with separate paths.
    ## Stop a node from SURB[0]'s path after forward delivery.
    ## Reply must arrive via SURB[1].
    const TestCodec = "/delayed-response/test/1.0.0"
    const ReadLen = 1024

    let testPayload = "forward message".toBytes()
    let responseData = "reply via surviving SURB".toBytes()

    var received = newFuture[seq[byte]]()
    var proceed = newFuture[void]()

    let destProto = LPProtocol.new()
    destProto.codec = TestCodec
    destProto.handler = proc(
        conn: Connection, proto: string
    ) {.async: (raises: [CancelledError]).} =
      try:
        received.complete(await conn.readLp(ReadLen))
        await proceed
        await conn.writeLp(responseData)
      except CatchableError as e:
        raiseAssert e.msg

    let (nodes, mock) = await setupMixNodesWithMock(
      10, destReadBehavior = Opt.some((codec: TestCodec, callback: readLp(ReadLen)))
    )

    let (destNode, _) = await setupDestNode(destProto)

    # Force separate SURB paths: nodes[2..4] for SURB 0, nodes[5..7] for SURB 1
    mock.surbPeerSets = @[
      nodes[2 .. 4].mapIt(it.switch.peerInfo.peerId),
      nodes[5 .. 7].mapIt(it.switch.peerInfo.peerId),
    ]

    await startNodes(nodes)
    defer:
      await stopDestNode(destNode)
      await stopNodes(nodes)

    let conn = mock
      .toConnection(
        destNode.toMixDestination(),
        TestCodec,
        MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(byte(2))),
      )
      .expect("could not build connection")

    await conn.writeLp(testPayload)

    check testPayload == await received.wait(10.seconds)

    # Stop a node from SURB[0]'s path
    let nodeToStop =
      nodes.filterIt(it.switch.peerInfo.peerId == mock.actualSurbPeers[0][0])[0]
    await nodeToStop.switch.stop()

    # Signal dest node to send reply — must arrive via SURB[1]
    proceed.complete()

    let response = await conn.readLp(ReadLen).wait(10.seconds)
    await conn.close()

    check:
      response == responseData
      mock.receivedPacketCount == 1

  asyncTest "multiple SURBs - both replies received, only one delivered":
    ## 2 SURBs, all paths healthy. Exit sends reply via ALL SURBs.
    ## Both replies arrive at the sender's mix layer,
    ## but only one is delivered to the application.
    let (nodes, mock) = await setupMixNodesWithMock(
      10, destReadBehavior = Opt.some((codec: PingCodec, callback: readExactly(32)))
    )

    let (destNode, pingProto) = await setupDestNode(Ping.new(rng = rng()))

    await startNodes(nodes)
    defer:
      await stopDestNode(destNode)
      await stopNodes(nodes)

    let conn = mock
      .toConnection(
        destNode.toMixDestination(),
        pingProto.codec,
        MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(byte(2))),
      )
      .expect("could not build connection")
    defer:
      await conn.close()

    let response = await pingProto.ping(conn)
    check response != 0.seconds

    # Second read: no more replies delivered
    expect LPStreamEOFError:
      var buf: byte
      await conn.readExactly(addr buf, 1)

    # Both SURB replies arrived at the mix layer
    checkUntilTimeout:
      mock.receivedPacketCount == 2

    # The first reply released the whole group, so the second found nothing —
    # group-atomic release, end to end.
    check mock.surbCredsLen == 0

  asyncTest "sender receives empty response when destination is unreachable":
    ## Exit node gets DialFailedError, sends empty reply via SURB,
    ## sender receives an empty response from readLp().
    let nodes = await setupMixNodes(
      10, destReadBehavior = Opt.some((codec: PingCodec, callback: readExactly(32)))
    )

    let (destNode, pingProto) = await setupDestNode(Ping.new(rng = rng()))
    let destPeerId = destNode.peerInfo.peerId
    let destAddr = destNode.peerInfo.addrs[0]
    await stopDestNode(destNode)

    startAndDeferStop(nodes)

    let conn = nodes[0]
      .toConnection(
        MixDestination.init(destPeerId, destAddr),
        pingProto.codec,
        MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(byte(1))),
      )
      .expect("could not build connection")
    defer:
      await conn.close()

    await conn.write(@[1.byte, 2, 3, 4, 5])

    let response = await conn.readLp(1024).wait(10.seconds)
    check response.len == 0

    # The reply, empty or not, releases the credentials it was issued against.
    check nodes[0].surbCredsLen == 0

  asyncTest "reply timeout releases the SURB credentials":
    ## Destination never answers, so no reply can ever come back. readOnce
    ## must give up and drop the credentials rather than hold them.
    const TestCodec = "/silent/test/1.0.0"

    let destProto = SilentProtocol.new(TestCodec)
    let nodes = await setupMixNodes(
      10,
      destReadBehavior = Opt.some((codec: TestCodec, callback: readLp(1024))),
      delayStrategy = Opt.some(DelayStrategy(FixedDelayStrategy(delay: 0))),
    )
    startAndDeferStop(nodes)

    let (destNode, _) = await setupDestNode(destProto)
    defer:
      await stopDestNode(destNode)

    let sender = nodes[0]
    check sender.surbCredsLen == 0

    let conn = sender
      .toConnection(
        destNode.toMixDestination(),
        TestCodec,
        MixParameters(
          expectReply: Opt.some(true),
          numSurbs: Opt.some(byte(2)),
          replyTimeout: Opt.some(2.seconds),
        ),
      )
      .expect("could not build connection")
    defer:
      await conn.close()

    # Declared last so it runs first: the handler is parked, and stopDestNode
    # would otherwise wait on it.
    defer:
      destProto.release()

    await conn.writeLp(@[1.byte, 2, 3])
    discard await destProto.receivedMessages.get().wait(10.seconds)
    check sender.surbCredsLen == 2

    # libp2p convention: a timeout surfaces as end-of-stream, not a distinct
    # error type, so existing protocol code needs no mix-specific handling.
    expect LPStreamEOFError:
      discard await conn.readLp(1024).wait(10.seconds)

    check sender.surbCredsLen == 0

  asyncTest "closing the connection releases credentials, and a second write is refused":
    ## Prompt reclamation well inside the store TTL, plus the single-exchange
    ## guard — both properties of one live connection, so one setup covers them.
    const TestCodec = "/silent-2/test/1.0.0"

    let destProto = SilentProtocol.new(TestCodec)
    let nodes = await setupMixNodes(
      10,
      destReadBehavior = Opt.some((codec: TestCodec, callback: readLp(1024))),
      delayStrategy = Opt.some(DelayStrategy(FixedDelayStrategy(delay: 0))),
    )
    startAndDeferStop(nodes)

    let (destNode, _) = await setupDestNode(destProto)
    defer:
      await stopDestNode(destNode)

    let sender = nodes[0]

    let conn = sender
      .toConnection(
        destNode.toMixDestination(),
        TestCodec,
        MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(byte(3))),
      )
      .expect("could not build connection")
    defer:
      destProto.release()

    await conn.writeLp(@[1.byte, 2, 3])
    discard await destProto.receivedMessages.get().wait(10.seconds)
    check sender.surbCredsLen == 3

    # A second reply would land in a queue nobody drains, so it is refused.
    expect LPStreamError:
      await conn.writeLp(@[4.byte, 5, 6])

    await conn.close()
    check sender.surbCredsLen == 0

  asyncTest "a send that never leaves the node releases its credentials":
    ## Every mix node is unreachable, so sendPacket fails after the reply
    ## credentials were already registered. No reply can ever release them,
    ## so the send path must.
    let nodes = await setupMixNodes(
      10, destReadBehavior = Opt.some((codec: PingCodec, callback: readExactly(32)))
    )

    let (destNode, pingProto) = await setupDestNode(Ping.new(rng = rng()))
    defer:
      await stopDestNode(destNode)

    await startNodes(nodes)
    defer:
      await stopNodes(nodes)

    let sender = nodes[0]

    # Stop every other node. They stay in the sender peerStore, so path
    # selection still succeeds and the failure lands in sendPacket.
    for node in nodes[1 ..^ 1]:
      await node.switch.stop()

    let conn = sender
      .toConnection(
        destNode.toMixDestination(),
        pingProto.codec,
        MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(byte(4))),
      )
      .expect("could not build connection")
    defer:
      await conn.close()

    expect LPStreamError:
      await conn.write(@[1.byte, 2, 3, 4, 5])

    check sender.surbCredsLen == 0

  asyncTest "forward path node down - hop 2 or exit":
    ## With 4 mix nodes the sender (node 0) has a pool of exactly 3 nodes.
    ## After sending, we identify the first hop, then stop one of the other two nodes.

    ## The high delay ensures intermediaries hold the packet long enough
    ## to stop the target node before it is forwarded.
    let delayStrategy: DelayStrategy = FixedDelayStrategy(delay: 1000)

    let nodes = await setupMixNodes(4, delayStrategy = Opt.some(delayStrategy))
    startAndDeferStop(nodes)

    let (destNode, nrProto) = await setupDestNode(NoReplyProtocol.new())
    defer:
      await stopDestNode(destNode)

    let sender = nodes[0]

    let conn = sender.toConnection(destNode.toMixDestination(), nrProto.codec).expect(
        "could not build connection"
      )
    defer:
      await conn.close()

    await conn.writeLp(@[1.byte, 2, 3])

    # Filter out the first hop
    let nodesToStop =
      nodes[1 ..^ 1].filterIt(not sender.switch.isConnected(it.switch.peerInfo.peerId))

    # Stop hop 2 or exit
    await nodesToStop[0].switch.stop()

    # Destination must never receive the message
    # Wait at least 5s to ensure failure is from the stopped node
    expect AsyncTimeoutError:
      discard await nrProto.receivedMessages.get().wait(5.seconds)

  asyncTest "skip and remove nodes with invalid multiaddress from pool":
    # This test validates that nodes with invalid multiaddrs are:
    # 1. Skipped during path construction
    # 2. Removed from the pool
    # 3. Message still succeeds if enough valid nodes remain

    # Setup all mix protocol nodes (needed for forwarding)
    let nodes = await setupMixNodes(10)

    # Create invalid node with a multiaddr missing transport layer
    let invalidPeerId = PeerId.random(rng()).expect("could not generate peerId")
    let invalidMultiAddr =
      MultiAddress.init("/ip4/0.0.0.0").expect("could not initialize invalid multiaddr")

    # Get valid keys from any node's pub info (read from pool before clearing)
    let validPubInfo = nodes[0].nodePool.get(nodes[1].switch.peerInfo.peerId).get()
    let (_, _, validMixPubKey, validLibp2pPubKey) = validPubInfo.get()

    let invalidPubInfo = MixPubInfo.init(
      invalidPeerId, invalidMultiAddr, validMixPubKey, validLibp2pPubKey
    )

    # Calculate how many valid nodes to include in the pool
    # We need at least PathLength nodes after both:
    # 1. Destination node is excluded from path selection
    # 2. Invalid node is removed from pool
    # So we need PathLength + 1 valid nodes minimum (3 + 1 = 4)
    # Since destination (nodes[1]) is one of them, we need 4 total valid nodes
    let validNodesCount = min(nodes.len - 1, PathLength + 1)
    check nodes.len - 1 >= PathLength + 1

    # Save pub info from pool before clearing (need it for re-population)
    var savedPubInfos: seq[MixPubInfo]
    for i in 1 ..< validNodesCount + 1:
      savedPubInfos.add(nodes[0].nodePool.get(nodes[i].switch.peerInfo.peerId).get())

    # Give the sender (node 0) a pool of the valid nodes and the invalid node.
    # The pool keeps its added nodes, so the test calls `remove` for each old node.
    let senderPool = nodes[0].nodePool
    for peerId in senderPool.peerIds():
      discard senderPool.remove(peerId)
    senderPool.add(savedPubInfos)
    senderPool.add(invalidPubInfo)

    # Verify pool has validNodesCount + 1 invalid node
    check senderPool.len == validNodesCount + 1

    # Setup destination node
    let nrProto = NoReplyProtocol.new()
    nodes[1].switch.mount(nrProto)

    # Start all switches - they're needed as intermediate nodes in the mix path
    # even though only sender (0) and destination (1) are doing protocol work
    startAndDeferStop(nodes)

    # Send messages in a loop until invalid node is encountered and removed
    # With validNodesCount valid nodes, one invalid node and PathLength=3, we need multiple attempts
    let testPayload = "test message".toBytes()
    var initialPoolSize = senderPool.len

    # Try up to 20 times to encounter the invalid node
    # Stop if pool size goes below PathLength (can't construct path anymore)
    for attempt in 0 ..< 20:
      if senderPool.len < PathLength:
        break

      let conn = nodes[0].toConnection(nodes[1].toMixDestination(), nrProto.codec)

      if conn.isErr:
        # If we can't build connection due to insufficient nodes, break
        break

      await conn.get().writeLp(testPayload)
      discard await nrProto.receivedMessages.get().wait(5.seconds)
      await conn.get().close()

      # Check if invalid node was removed
      if senderPool.len < initialPoolSize:
        break

    # Verify invalid node was removed from pool (the valid nodes remain)
    check senderPool.len == validNodesCount

  asyncTest "the hop dial handler sees a successful, a cancelled and a failed dial":
    ## The first send dials a live hop. Then the test puts three fake hops in
    ## the pool in place of the live hops. The fake hops point at a server that
    ## never answers, so the next dial stays in the handshake until the test
    ## cancels the write. Then the test stops the server, so the last dial
    ## fails.
    let nodes = await ephemeralMixNodes(5)
    defer:
      await stopNodes(nodes)
    let sender = nodes[0]
    let destNode = nodes[4]
    let echoProto = EchoProtocol.new()
    await echoProto.start()
    destNode.switch.mount(echoProto)
    for node in nodes:
      node.registerDestReadBehavior(echoProto.codec, readLp(EchoMaxReadLen))
    var reports: seq[
      tuple[
        peerId: PeerId,
        addresses: seq[MultiAddress],
        outcome: MixHopDialOutcome,
        hadConnection: bool,
        error: ref CatchableError,
      ]
    ]
    sender.onHopDial = proc(
        peerId: PeerId,
        addresses: seq[MultiAddress],
        outcome: MixHopDialOutcome,
        hadConnection: bool,
        error: ref CatchableError,
    ) {.gcsafe, raises: [].} =
      reports.add((peerId, addresses, outcome, hadConnection, error))

    block:
      let conn = sender
        .toConnection(destNode.toMixDestination(), echoProto.codec)
        .expect("could not build connection")
      defer:
        await conn.close()
      await conn.writeLp(@[1.byte, 2, 3])
    check:
      reports.len == 1
      reports[0].outcome == MixHopDialOutcome.Succeeded
      not reports[0].hadConnection
      reports[0].peerId in sender.nodePool.peerIds()
      reports[0].addresses == @[sender.nodePool.get(reports[0].peerId).get().multiAddr]
      reports[0].error.isNil

    let server = UnresponsiveServer.new()
    defer:
      await server.stop()
    for hop in nodes[1 .. 3]:
      discard sender.nodePool.remove(hop.localMixPubInfo().peerId)
    let hops = fakeHops(3, server.address)
    sender.nodePool.add(hops)
    for peerId in sender.switch.connectedPeers():
      await sender.switch.disconnect(peerId)
    block:
      let conn = sender
        .toConnection(destNode.toMixDestination(), echoProto.codec)
        .expect("could not build connection")
      defer:
        await conn.close()
      let sending = conn.writeLp(@[1.byte, 2, 3])
      checkUntilTimeout:
        server.accepted > 0
      await sending.cancelAndWait()
    check:
      reports.len == 2
      reports[1].outcome == MixHopDialOutcome.Cancelled
      not reports[1].hadConnection
      reports[1].peerId in hops.mapIt(it.peerId)
      reports[1].addresses == @[server.address]
      reports[1].error.isNil

    await server.stop()
    block:
      let conn = sender
        .toConnection(destNode.toMixDestination(), echoProto.codec)
        .expect("could not build connection")
      defer:
        await conn.close()
      expect LPStreamError:
        await conn.writeLp(@[1.byte, 2, 3])
    check:
      reports.len == 3
      reports[2].outcome == MixHopDialOutcome.Failed
      not reports[2].hadConnection
      reports[2].peerId in hops.mapIt(it.peerId)
      reports[2].addresses == @[server.address]
      reports[2].error of DialFailedError
