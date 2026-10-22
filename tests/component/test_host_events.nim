# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results
import libp2p/[switch, connmanager, peerid]
import libp2p_mix
import ../tools/[peer_source, lifecycle, unittest]
import ../utils

suite "Host event integration":
  asyncTeardown:
    checkTrackers()

  asyncTest "a host listener updates the host view and detaches":
    let nodes = await startTestMixNodes(4)
    defer:
      await stopNodes(nodes)
    let sender = nodes[0]
    let target = nodes[1].localMixPubInfo().peerId
    let source = testPeerSource(sender.brokerCtx)
    source.exclude(target)
    check sender.brokerCtx.get(target).get().isNone
    let joined = newAsyncEvent()
    let listener: PeerEventHandler = proc(
        peerId: PeerId, event: PeerEvent
    ) {.async: (raises: [CancelledError]), gcsafe.} =
      # The host restores the peer when libp2p reports the connection.
      source.restore(peerId)
      joined.fire()
    sender.switch.addPeerEventHandler(listener, PeerEventKind.Joined)
    try:
      await sender.switch.connect(target, nodes[1].switch.peerInfo.addrs)
      await joined.wait().wait(2.seconds)
      check sender.brokerCtx.get(target).get().isSome
      check sender.brokerCtx.count([]).get() == 3
    finally:
      sender.switch.removePeerEventHandler(listener, PeerEventKind.Joined)
    await sender.switch.disconnect(target)
    source.exclude(target)
    let rejoined = newAsyncEvent()
    let rejoinedListener: PeerEventHandler = proc(
        peerId: PeerId, event: PeerEvent
    ) {.async: (raises: [CancelledError]), gcsafe.} =
      rejoined.fire()
    sender.switch.addPeerEventHandler(rejoinedListener, PeerEventKind.Joined)
    try:
      await sender.switch.connect(target, nodes[1].switch.peerInfo.addrs)
      await rejoined.wait().wait(2.seconds)
      check sender.brokerCtx.get(target).get().isNone
      check sender.brokerCtx.count([]).get() == 2
    finally:
      sender.switch.removePeerEventHandler(rejoinedListener, PeerEventKind.Joined)
