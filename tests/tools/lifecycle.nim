# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import chronos, sequtils
import libp2p/switch
import results
import libp2p_mix/mix_protocol
import ./futures

proc startNodes*[T](nodes: seq[T]) {.async.} =
  await allFuturesRaising(nodes.mapIt(it.switch.start()))
  when compiles(nodes[0].setLocalMultiAddr(nodes[0].switch.peerInfo.addrs[0])):
    for node in nodes:
      node.setLocalMultiAddr(node.switch.peerInfo.addrs[0]).expect("bound address")
    for node in nodes:
      for other in nodes:
        if node != other and node.nodePool.contains(other.localMixPubInfo().peerId):
          node.nodePool.add(other.localMixPubInfo())
  when compiles(nodes[0].start()):
    await allFuturesRaising(nodes.mapIt(it.start()))

proc stopNodes*[T](nodes: seq[T]) {.async.} =
  when compiles(nodes[0].stop()):
    await allFuturesRaising(nodes.mapIt(it.stop()))
  await allFuturesRaising(nodes.mapIt(it.switch.stop()))

template startAndDeferStop*[T](nodes: seq[T]): untyped =
  await startNodes(nodes)
  defer:
    await stopNodes(nodes)
