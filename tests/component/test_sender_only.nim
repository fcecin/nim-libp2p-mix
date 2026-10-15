# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results, sequtils
import libp2p/[protocols/ping, peerid, switch]
import libp2p_mix
import libp2p_mix/mix_protocol

import ../tools/[lifecycle, unittest, crypto]
import ../utils

suite "Mix Protocol - Sender-only role":
  asyncTeardown:
    checkTrackers()

  asyncTest "a sender-only node sends and receives its reply":
    let nodes = await setupMixNodes(
      10, destReadBehavior = Opt.some((codec: PingCodec, callback: readExactly(32)))
    )
    nodes[0].role = MixNodeRole.SenderOnly
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

  asyncTest "a sender-only node drops a packet that names it as a hop":
    ## The sender's pool holds three nodes, so every path uses all three and
    ## one of them is the sender-only node. No message reaches the
    ## destination through it. With the full role, the same path delivers.
    let nodes = await setupMixNodes(4)
    let hop = nodes[1]
    hop.role = MixNodeRole.SenderOnly
    let sender = nodes[0]
    # The pool of the sender: the three other nodes and nothing else.
    for peerId in sender.nodePool.peerIds():
      if peerId notin nodes[1 .. 3].mapIt(it.switch.peerInfo.peerId):
        discard sender.nodePool.remove(peerId)
    startAndDeferStop(nodes)

    let (destNode, nrProto) = await setupDestNode(NoReplyProtocol.new())
    defer:
      await stopDestNode(destNode)

    let dropped = sender.toConnection(destNode.toMixDestination(), nrProto.codec).expect(
        "could not build connection"
      )
    await dropped.writeLp(@[1.byte, 2, 3])
    await dropped.close()
    check not await nrProto.receivedMessages.get().withTimeout(2.seconds)

    hop.role = MixNodeRole.Full
    let delivered = sender.toConnection(destNode.toMixDestination(), nrProto.codec).expect(
        "could not build connection"
      )
    await delivered.writeLp(@[4.byte, 5, 6])
    await delivered.close()
    let receivedMsg = await nrProto.receivedMessages.get().wait(2.seconds)
    check receivedMsg.data == @[4.byte, 5, 6]
