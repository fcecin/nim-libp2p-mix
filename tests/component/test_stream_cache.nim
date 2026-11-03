# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/sequtils
import chronos, results
import libp2p/[switch, peerid, multiaddress]
import libp2p_mix
import libp2p_mix/[mix_protocol, mix_node]
import ../tools/[lifecycle, unittest, crypto]
import ../utils

const ReplyParams = MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(1'u8))

proc exchange(
    sender: MixProtocol, destination: MixDestination, codec: string, value: byte
) {.async.} =
  let conn = sender.toConnection(destination, codec, ReplyParams).get()
  defer:
    await conn.close()
  await conn.writeLp(@[value]).wait(5.seconds)
  check (await conn.readLp(1024).wait(5.seconds)) == @[value]

suite "Hop stream cache":
  asyncTeardown:
    checkTrackers()

  asyncTest "concurrent requests and retries reuse one cached stream per peer":
    let nodes = await setupMixNodes(5)
    await startNodes(nodes)
    defer:
      await stopNodes(nodes)
    let sender = nodes[0]
    let echo = EchoProtocol.new()
    await echo.start()
    nodes[^1].switch.mount(echo)
    for node in nodes:
      node.registerDestReadBehavior(echo.codec, readLp(1024))
    for round in 0 .. 1:
      var pending: seq[Future[void]]
      for i in 0 ..< 8:
        let destination =
          if i mod 2 == 0:
            nodes[^1].switch.toMixDestination()
          else:
            MixDestination.exitNode(nodes[^1].localMixPubInfo().peerId)
        pending.add(exchange(sender, destination, echo.codec, i.byte))
      try:
        await allFutures(pending).wait(10.seconds)
        for request in pending:
          await request
      finally:
        await allFutures(pending.mapIt(it.cancelAndWait()))
      let streams = outgoingMixStreams(sender.switch)
      check streams.len > 0
      # One cached stream for each peer. A second stream to the same peer is
      # the duplicate that this test exists to catch.
      check streams.mapIt(it.peerId).deduplicate().len == streams.len
      check sender.surbCredsLen == 0
      if round == 0:
        # Close the cached streams and keep the cache entries, as a peer reset does.
        await allFutures(streams.mapIt(it.close()))

  asyncTest "protocol stop cancels a dial in flight and caches nothing":
    let nodes = await setupMixNodes(1)
    await startNodes(nodes)
    defer:
      await stopNodes(nodes)

    var accepted = 0
    var held: seq[StreamTransport]
    let server = createStreamServer(initTAddress("127.0.0.1:0"), flags = {ReuseAddr})
    proc acceptLoop() {.async.} =
      while true:
        held.add(await server.accept())
        inc accepted

    let acceptor = acceptLoop()
    defer:
      await acceptor.cancelAndWait()
      for transport in held:
        await transport.closeWait()
      await server.closeWait()

    let hop = MixNodeInfo.generateRandom(0, rng())
    let hopAddr = MultiAddress
      .init("/ip4/127.0.0.1/tcp/" & $int(server.localAddress().port))
      .expect("address")
    let sending = nodes[0].sendCoverPacket(hop.peerId, hopAddr, @[1.byte])
    checkUntilTimeout:
      accepted == 1
    check not sending.finished

    await nodes[0].stop()
    expect CancelledError:
      discard await sending.wait(2.seconds)
    check outgoingMixStreams(nodes[0].switch).len == 0
    check (await nodes[0].sendCoverPacket(hop.peerId, hopAddr, @[1.byte])).isErr
    check accepted == 1

    await nodes[0].start()
    let again = nodes[0].sendCoverPacket(hop.peerId, hopAddr, @[1.byte])
    checkUntilTimeout:
      accepted == 2
    await again.cancelAndWait()
