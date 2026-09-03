# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import algorithm, chronos, results, stew/byteutils, sequtils, tables
import libp2p/[protocols/ping, peerid, switch, builders]
import libp2p_mix
import libp2p_mix/mix_protocol
import libp2p_mix/delay_strategy
import libp2p_mix/[entry_connection, sphinx]

import ../tools/[lifecycle, unittest, crypto]
import ../utils

suite "Mix Protocol - Message Delivery":
  asyncTeardown:
    checkTrackers()

  asyncTest "expect reply, exit != destination":
    let nodes = await setupMixNodes(
      10, destReadBehavior = Opt.some((codec: PingCodec, callback: readExactly(32)))
    )
    startAndDeferStop(nodes)

    let (destNode, pingProto) = await setupDestNode(Ping.new(rng = rng()))
    defer:
      await stopDestNode(destNode)

    let conn = nodes[0]
      .toConnection(
        destNode.toMixDestination(),
        pingProto.codec,
        MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(byte(1))),
      )
      .expect("could not build connection")

    let response = await pingProto.ping(conn)
    await conn.close()

    check response != 0.seconds

  asyncTest "expect reply, exit != destination, with a reply anchor":
    ## The anchor delivers the reply to the sender. Here every node is
    ## reachable, so the test shows that the anchor does not break delivery;
    ## the position of the anchor on the return path is a unit test.
    let nodes = await setupMixNodes(
      10, destReadBehavior = Opt.some((codec: PingCodec, callback: readExactly(32)))
    )
    startAndDeferStop(nodes)
    let (destNode, pingProto) = await setupDestNode(Ping.new(rng = rng()))
    defer:
      await stopDestNode(destNode)
    let anchor = nodes[5].switch.peerInfo.peerId
    let conn = nodes[0]
      .toConnection(
        destNode.toMixDestination(),
        pingProto.codec,
        MixParameters(
          expectReply: Opt.some(true),
          numSurbs: Opt.some(byte(1)),
          replyAnchor: Opt.some(anchor),
        ),
      )
      .expect("could not build connection")
    let response = await pingProto.ping(conn)
    await conn.close()
    check response != 0.seconds

  asyncTest "the sent path is exposed and the avoided hops stay out of the next path":
    ## A caller whose attempt got no reply names the hops of that attempt as
    ## `avoidPeers`; with enough other pool nodes they stay out of the next
    ## forward path. The path lists the hops and the exit node last.
    let nodes = await setupMixNodes(
      10, destReadBehavior = Opt.some((codec: PingCodec, callback: readExactly(32)))
    )
    startAndDeferStop(nodes)
    let (destNode, pingProto) = await setupDestNode(Ping.new(rng = rng()))
    defer:
      await stopDestNode(destNode)
    let pool = nodes[0].nodePool.peerIds()

    let first = nodes[0]
      .toConnection(
        destNode.toMixDestination(),
        pingProto.codec,
        MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(byte(1))),
      )
      .expect("could not build connection")
    check (await pingProto.ping(first)) != 0.seconds
    let firstPath = MixEntryConnection(first).sentPath()
    await first.close()
    check:
      firstPath.len == PathLength
      firstPath.allIt(it in pool)
      firstPath.deduplicate().len == PathLength

    let avoided = firstPath[0 ..< PathLength - 1]
    let second = nodes[0]
      .toConnection(
        destNode.toMixDestination(),
        pingProto.codec,
        MixParameters(
          expectReply: Opt.some(true), numSurbs: Opt.some(byte(1)), avoidPeers: avoided
        ),
      )
      .expect("could not build connection")
    check (await pingProto.ping(second)) != 0.seconds
    let secondPath = MixEntryConnection(second).sentPath()
    await second.close()
    check:
      secondPath.len == PathLength
      secondPath.allIt(it notin avoided)

  asyncTest "with a small pool, as many avoided hops leave the path as the pool allows":
    ## Five nodes: the sender and four others in its pool. Two avoided hops:
    ## dropping both would leave two candidates, below the path length, so one
    ## of them leaves and the other stays in the draw.
    let nodes = await setupMixNodes(
      5, destReadBehavior = Opt.some((codec: PingCodec, callback: readExactly(32)))
    )
    startAndDeferStop(nodes)
    let (destNode, pingProto) = await setupDestNode(Ping.new(rng = rng()))
    defer:
      await stopDestNode(destNode)
    let others = nodes[1 .. ^1].mapIt(it.switch.peerInfo.peerId)
    let avoided = others[0 .. 1]
    for _ in 0 ..< 8:
      let conn = nodes[0]
        .toConnection(
          destNode.toMixDestination(),
          pingProto.codec,
          MixParameters(
            expectReply: Opt.some(true),
            numSurbs: Opt.some(byte(1)),
            avoidPeers: avoided,
          ),
        )
        .expect("could not build connection")
      check (await pingProto.ping(conn)) != 0.seconds
      let path = MixEntryConnection(conn).sentPath()
      await conn.close()
      # Three candidates remain for three positions, so every path holds
      # exactly one avoided hop: the one the pool could not spare, drawn at
      # random each time.
      check path.filterIt(it in avoided).len == 1

  asyncTest "expect no reply, exit != destination":
    let nodes = await setupMixNodes(10)
    startAndDeferStop(nodes)

    let (destNode, nrProto) = await setupDestNode(NoReplyProtocol.new())
    defer:
      await stopDestNode(destNode)

    let conn = nodes[0].toConnection(destNode.toMixDestination(), nrProto.codec).expect(
        "could not build connection"
      )

    let data = @[1.byte, 2, 3, 4, 5]
    await conn.writeLp(data)
    await conn.close()

    let receivedMsg = await nrProto.receivedMessages.get().wait(2.seconds)
    check data == receivedMsg.data

    # assert anonymity of the sender
    let sender = nodes[0].switch.peerInfo.peerId
    let destination = destNode.peerInfo.peerId
    check:
      receivedMsg.connPeerId != sender
      receivedMsg.connPeerId != destination
      receivedMsg.connPeerId in nodes.mapIt(it.switch.peerInfo.peerId)

  asyncTest "multiple sequential messages on same connection":
    let nodes = await setupMixNodes(10)
    startAndDeferStop(nodes)

    let (destNode, nrProto) = await setupDestNode(NoReplyProtocol.new())
    defer:
      await stopDestNode(destNode)

    let conn = nodes[0].toConnection(destNode.toMixDestination(), nrProto.codec).expect(
        "could not build connection"
      )
    defer:
      await conn.close()

    let messages = (0 ..< 10).mapIt(newSeqWith(5, it.byte))

    for msg in messages:
      await conn.writeLp(msg)

    var received: seq[seq[byte]]
    for _ in messages:
      let msg = await nrProto.receivedMessages.get().wait(2.seconds)
      received.add(msg.data)

    check received.sorted == messages

  asyncTest "path nodes are random - exit node varies across messages":
    let nodes = await setupMixNodes(10)
    startAndDeferStop(nodes)

    let (destNode, nrProto) = await setupDestNode(NoReplyProtocol.new())
    defer:
      await stopDestNode(destNode)

    # Send multiple messages and track which mix node delivered each one
    const numMessages = 20
    var exitNodes: Table[PeerId, int]

    for i in 0 ..< numMessages:
      let conn = nodes[0]
        .toConnection(destNode.toMixDestination(), nrProto.codec)
        .expect("could not build connection")

      await conn.writeLp(@[byte(i)])
      await conn.close()

      let receivedMsg = await nrProto.receivedMessages.get().wait(2.seconds)
      exitNodes.mgetOrPut(receivedMsg.connPeerId, 0).inc()

    # With 20 messages and 9 eligible nodes,
    # random selection must produce at least 3 distinct exit nodes.
    # Sender must never be exit and destination must never be exit.
    let sender = nodes[0].switch.peerInfo.peerId
    let destination = destNode.peerInfo.peerId
    check:
      exitNodes.len >= 3
      sender notin exitNodes
      destination notin exitNodes

  when defined(libp2p_mix_experimental_exit_is_dest):
    asyncTest "expect reply, exit == destination":
      let nodes = await setupMixNodes(
        10, destReadBehavior = Opt.some((codec: PingCodec, callback: readExactly(32)))
      )

      let destNode = nodes[^1]
      let pingProto = Ping.new(rng = rng())
      destNode.switch.mount(pingProto)

      startAndDeferStop(nodes)

      let conn = nodes[0]
        .toConnection(
          MixDestination.exitNode(destNode.switch.peerInfo.peerId),
          pingProto.codec,
          MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(byte(1))),
        )
        .expect("could not build connection")

      let response = await pingProto.ping(conn)
      await conn.close()

      check response != 0.seconds

  asyncTest "length-prefixed protocol - verify readLp fix":
    ## This test verifies the fix for the length prefix bug where responses
    ## from protocols using readLp() were losing their length prefix when
    ## flowing back through the mix network.
    let testPayload = "Privacy for everyone and transparency for people in power is one way to reduce corruption".toBytes()
    let echoProto = EchoProtocol.new()

    let nodes = await setupMixNodes(
      10,
      destReadBehavior =
        Opt.some((codec: echoProto.codec, callback: readLp(EchoMaxReadLen))),
    )

    let destNode = nodes[^1]
    destNode.switch.mount(echoProto)

    startAndDeferStop(nodes)

    let conn = nodes[0]
      .toConnection(
        destNode.toMixDestination(),
        echoProto.codec,
        MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(byte(1))),
      )
      .expect("could not build connection")

    await conn.writeLp(testPayload)

    # Read response - this should work correctly with the length prefix fix
    let response = await conn.readLp(EchoMaxReadLen)
    await conn.close()

    check response == testPayload

  asyncTest "intermediate nodes apply delay":
    let delay: Delay = 300
    let delayStrategy: DelayStrategy = FixedDelayStrategy(delay: delay)
    let nodes = await setupMixNodes(10, delayStrategy = Opt.some(delayStrategy))
    startAndDeferStop(nodes)

    let (destNode, nrProto) = await setupDestNode(NoReplyProtocol.new())
    defer:
      await stopDestNode(destNode)

    let conn = nodes[0].toConnection(destNode.toMixDestination(), nrProto.codec).expect(
        "could not build connection"
      )
    defer:
      await conn.close()

    let startTime = Moment.now()
    let data = @[1.byte, 2, 3, 4, 5]
    await conn.writeLp(data)

    let receivedMsg = await nrProto.receivedMessages.get().wait(2.seconds)
    let elapsed = Moment.now() - startTime

    # Path == 3, 2 intermediate hops apply delay, exit node does not.
    check:
      receivedMsg.data == data
      elapsed >= (delay * 2).toDuration

  asyncTest "concurrent messages with SURB replies":
    let echoProto = EchoProtocol.new()

    let nodes = await setupMixNodes(
      10,
      destReadBehavior =
        Opt.some((codec: echoProto.codec, callback: readLp(EchoMaxReadLen))),
    )
    startAndDeferStop(nodes)

    let (destNode, _) = await setupDestNode(echoProto)
    defer:
      await stopDestNode(destNode)

    proc sendAndReceive(
        node: MixProtocol, dest: MixDestination, data: seq[byte]
    ): Future[seq[byte]] {.async.} =
      let conn = node
        .toConnection(
          dest,
          echoProto.codec,
          MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(byte(1))),
        )
        .expect("could not build connection")
      await conn.writeLp(data)
      let response = await conn.readLp(EchoMaxReadLen)
      await conn.close()
      return response

    # Send concurrent echo requests with unique payload from different nodes
    const numConcurrent = 5
    var futs: seq[Future[seq[byte]]]

    for i in 0 ..< numConcurrent:
      let payload = newSeqWith(4, i.byte)
      futs.add(sendAndReceive(nodes[i], destNode.toMixDestination(), payload))

    let responses = await allFinished(futs)

    # Every sender must receive exactly their own payload back
    for i, fut in responses:
      let expected = newSeqWith(4, i.byte)
      check:
        fut.completed()
        fut.value() == expected
