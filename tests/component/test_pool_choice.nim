# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results
import libp2p/switch
import libp2p_mix
import libp2p_mix/[mix_pool, mix_protocol]
import ../tools/[lifecycle, unittest, host_pool]
import ../utils

proc exchangeThroughPool(useHostStore: bool) {.async.} =
  let nodes = await startTestMixNodes(5, useHostStore = useHostStore)
  defer:
    await stopNodes(nodes)
  let echo = EchoProtocol.new()
  await echo.start()
  nodes[^1].switch.mount(echo)
  for node in nodes:
    node.registerDestReadBehavior(echo.codec, readLp(1024))
  for fixedExit in [false, true]:
    let destination =
      if fixedExit:
        MixDestination.exitNode(nodes[^1].localMixPubInfo().peerId)
      else:
        nodes[^1].switch.toMixDestination()
    let conn = nodes[0]
      .toConnection(
        destination,
        echo.codec,
        MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(1'u8)),
      )
      .get()
    try:
      await conn.writeLp(@[1'u8, 2, 3]).wait(5.seconds)
      check (await conn.readLp(1024).wait(5.seconds)) == @[1'u8, 2, 3]
    finally:
      await conn.close()
  check (await nodes[0].buildCoverPacket()).isOk
  check nodes[0].surbCredsLen == 0

suite "Either pool class behind one MixProtocol":
  asyncTeardown:
    checkTrackers()

  asyncTest "the stock pool supports requests, replies and cover":
    await exchangeThroughPool(false)

  asyncTest "a host pool supports requests, replies and cover":
    await exchangeThroughPool(true)
