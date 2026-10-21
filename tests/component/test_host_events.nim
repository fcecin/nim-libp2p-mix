# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results
import libp2p/[switch, connmanager, peerid]
import libp2p_mix
import ../tools/[host_pool, lifecycle, unittest]
import ../utils

suite "Host pool and libp2p events":
  asyncTeardown:
    checkTrackers()

  asyncTest "a host listener updates its pool and detaches":
    let nodes = await startTestMixNodes(4)
    defer:
      await stopNodes(nodes)
    let sender = nodes[0]
    let target = nodes[1].localMixPubInfo().peerId
    let host = sender.hostPool
    host.exclude(target)
    check sender.pool.usablePeer(target).get().isNone
    let joined = newAsyncEvent()
    let listener: PeerEventHandler = proc(
        peerId: PeerId, event: PeerEvent
    ) {.async: (raises: [CancelledError]), gcsafe.} =
      # The host restores the peer when libp2p reports the connection.
      host.restore(peerId)
      joined.fire()
    sender.switch.addPeerEventHandler(listener, PeerEventKind.Joined)
    try:
      await sender.switch.connect(target, nodes[1].switch.peerInfo.addrs)
      await joined.wait().wait(2.seconds)
      check sender.pool.usablePeer(target).get().isSome
      check sender.pool.count([]).get() == 3
    finally:
      sender.switch.removePeerEventHandler(listener, PeerEventKind.Joined)
    await sender.switch.disconnect(target)
    host.exclude(target)
    let rejoined = newAsyncEvent()
    let rejoinedListener: PeerEventHandler = proc(
        peerId: PeerId, event: PeerEvent
    ) {.async: (raises: [CancelledError]), gcsafe.} =
      rejoined.fire()
    sender.switch.addPeerEventHandler(rejoinedListener, PeerEventKind.Joined)
    try:
      await sender.switch.connect(target, nodes[1].switch.peerInfo.addrs)
      await rejoined.wait().wait(2.seconds)
      check sender.pool.usablePeer(target).get().isNone
      check sender.pool.count([]).get() == 2
    finally:
      sender.switch.removePeerEventHandler(rejoinedListener, PeerEventKind.Joined)
