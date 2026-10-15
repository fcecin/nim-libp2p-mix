# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results, sequtils
import libp2p/[peerid, switch, multiaddress]
import libp2p_mix
import libp2p_mix/mix_protocol
import ./tools/[unittest, crypto, lifecycle]
import ./utils

suite "One dial per peer at a time":
  asyncTeardown:
    checkTrackers()

  asyncTest "two concurrent requests for a connection to the same peer share one dial":
    let nodes = await setupMixNodes(2)
    startAndDeferStop(nodes)
    let target = nodes[1]
    let targetId = target.switch.peerInfo.peerId
    let targetAddrs = target.switch.peerInfo.addrs
    let first = nodes[0].getConn(targetId, targetAddrs, @[MixProtocolID])
    let second = nodes[0].getConn(targetId, targetAddrs, @[MixProtocolID])
    let connA = await first
    let connB = await second
    check:
      connA == connB
      nodes[0].dialsInFlightLen() == 0
    await connA.close()

  asyncTest "a request after the dial completed reuses the pooled connection":
    let nodes = await setupMixNodes(2)
    startAndDeferStop(nodes)
    let target = nodes[1]
    let targetId = target.switch.peerInfo.peerId
    let targetAddrs = target.switch.peerInfo.addrs
    let connA = await nodes[0].getConn(targetId, targetAddrs, @[MixProtocolID])
    let connB = await nodes[0].getConn(targetId, targetAddrs, @[MixProtocolID])
    check connA == connB
    await connA.close()
