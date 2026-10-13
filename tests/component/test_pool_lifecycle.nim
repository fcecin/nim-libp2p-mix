# SPDX-License-Identifier: Apache-2.0 OR MIT

{.used.}

import chronos, results
import libp2p/[switch, dialer, multiaddress, peerid]
import libp2p/stream/connection
import libp2p_mix
import libp2p_mix/[mix_protocol, delay_strategy]
import ../utils
import ../tools/[unittest, lifecycle, crypto]

type GateDialer = ref object of Dialer
  inner: Dialer
  gate, entered: AsyncEvent
  attempts: seq[PeerId]
  cancelled: int
  blocked: bool

method connect(
    self: GateDialer,
    peerId: PeerId,
    addrs: seq[MultiAddress],
    forceDial = false,
    reuseConnection = true,
    dir = Direction.Out,
) {.async: (raises: [DialFailedError, CancelledError]).} =
  self.attempts.add(peerId)
  self.entered.fire()
  if self.blocked:
    try:
      await self.gate.wait()
    except CancelledError as exc:
      self.cancelled.inc()
      raise exc
  await self.inner.connect(peerId, addrs, forceDial, reuseConnection, dir)

proc ephemeralNodes(count: int): Future[seq[MixProtocol]] {.async.} =
  var nodes: seq[MixProtocol]
  for _ in 0 ..< count:
    var info = MixNodeInfo.generateRandom(0, rng())
    info.multiAddr = MultiAddress.init("/ip4/127.0.0.1/tcp/0").tryGet()
    let sw = createSwitch(info.multiAddr, Opt.some(info.libp2pPrivKey))
    let node = MixProtocol.new(
      info,
      sw,
      poolConfig = MixPoolConfig(addressPolicy: defaultAddressPolicy),
      delayStrategy = Opt.some(DelayStrategy(NoSamplingDelayStrategy.new(rng()))),
    )
    sw.mount(node)
    nodes.add(node)
  await startNodes(nodes)
  for node in nodes:
    check node.setLocalMultiAddr(node.switch.peerInfo.addrs[0]).isOk
  for node in nodes:
    for other in nodes:
      if node != other:
        discard node.nodePool.remove(other.localMixPubInfo().peerId)
        node.nodePool.ingest(other.localMixPubInfo())
  return nodes

suite "Mix pool and reply lifecycle":
  asyncTest "a sender with an unreachable self address receives real replies in both modes":
    let nodes = await ephemeralNodes(5)
    defer:
      await stopNodes(nodes)
    let sender = nodes[0]
    let destination = nodes[4]
    let echo = EchoProtocol.new()
    await echo.start()
    destination.switch.mount(echo)
    for node in nodes:
      node.registerDestReadBehavior(echo.codec, readLp(EchoMaxReadLen))
    check sender.setLocalMultiAddr(MultiAddress.init("/ip4/192.0.2.1/tcp/1").tryGet()).isOk
    for node in nodes[1 .. ^1]:
      discard node.nodePool.remove(sender.localMixPubInfo().peerId)
    for mode in 0 .. 1:
      let target =
        if mode == 0:
          destination.toMixDestination()
        else:
          MixDestination.exitNode(destination.localMixPubInfo().peerId)
      let conn = sender
        .toConnection(
          target,
          echo.codec,
          MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(1'u8)),
        )
        .tryGet()
      try:
        await conn.writeLp(@[1.byte, 2, 3]).wait(5.seconds)
        check (await conn.readLp(32).wait(5.seconds)) == @[1.byte, 2, 3]
        check sender.surbCredsLen == 0
      finally:
        await conn.close()
    let path = sender
      .replyPath(
        destination.localMixPubInfo().peerId, destination.localMixPubInfo().peerId
      )
      .tryGet()
    check sender.switch.isConnected(path[^2].peerId)
    check path[0].peerId != path[1].peerId
    check path[^1].multiAddr == sender.localMixPubInfo().multiAddr
    for peerId in sender.switch.connectedPeers():
      await sender.switch.disconnect(peerId)
    check sender.replyPath(
      destination.localMixPubInfo().peerId, destination.localMixPubInfo().peerId
    ).isErr

  asyncTest "concurrent preparation shares dials and stop cancels them before restart":
    let nodes = await ephemeralNodes(4)
    defer:
      await stopNodes(nodes)
    let sender = nodes[0]
    let target = nodes[3].localMixPubInfo().peerId
    let gate = GateDialer(
      inner: sender.switch.dialer,
      gate: newAsyncEvent(),
      entered: newAsyncEvent(),
      blocked: true,
    )
    sender.switch.dialer = gate
    let first = sender.prepareReplyPath(target, target)
    let second = sender.prepareReplyPath(target, target)
    await gate.entered.wait().wait(2.seconds)
    check gate.attempts.len == 2
    check sender.pendingDials == 2
    await first.cancelAndWait()
    check not second.finished
    check gate.cancelled == 0
    await sender.stop()
    check (await second).isErr
    check gate.cancelled == 2
    check sender.pendingDials == 0
    check sender.nodePool.counters.dialFailed == 0
    gate.blocked = false
    await sender.start()
    check (await sender.prepareReplyPath(target, target)).isOk
    let path = sender.replyPath(target, target).tryGet()
    check sender.switch.isConnected(path[^2].peerId)
    sender.switch.dialer = gate.inner

  asyncTest "closing a request cancels its write during reply preparation":
    let nodes = await ephemeralNodes(4)
    defer:
      await stopNodes(nodes)
    let sender = nodes[0]
    let target = nodes[3].localMixPubInfo().peerId
    let hook = GateDialer(
      inner: sender.switch.dialer,
      gate: newAsyncEvent(),
      entered: newAsyncEvent(),
      blocked: true,
    )
    sender.switch.dialer = hook
    sender.registerDestReadBehavior("/close/test", readLp(32))
    let conn = sender
      .toConnection(
        MixDestination.exitNode(target),
        "/close/test",
        MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(1'u8)),
      )
      .expect("connection")
    let writing = conn.writeLp(@[1.byte])
    await hook.entered.wait().wait(2.seconds)
    expect LPStreamError:
      await conn.writeLp(@[2.byte])
    await conn.close()
    check writing.cancelled
    check sender.surbCredsLen == 0
    await sender.stop()
    check sender.pendingDials == 0
    check sender.nodePool.counters.dialFailed == 0
    sender.switch.dialer = hook.inner

  asyncTest "cancelled fire and forget entry dial records one hop failure":
    let nodes = await ephemeralNodes(4)
    defer:
      await stopNodes(nodes)
    let sender = nodes[0]
    let auxiliary = createSwitch()
    await auxiliary.start()
    defer:
      await auxiliary.stop()
    await sender.switch.connect(auxiliary.peerInfo.peerId, auxiliary.peerInfo.addrs)
    let gate = GateDialer(
      inner: sender.switch.dialer,
      gate: newAsyncEvent(),
      entered: newAsyncEvent(),
      blocked: true,
    )
    sender.switch.dialer = gate
    let pending = sender.anonymizeLocalProtocolSend(
      nil,
      @[1.byte],
      "/any/codec",
      MixDestination.forwardToAddr(
        auxiliary.peerInfo.peerId, auxiliary.peerInfo.addrs[0]
      ),
      0,
    )
    await gate.entered.wait().wait(2.seconds)
    check gate.attempts.len == 1
    await pending.cancelAndWait()
    check sender.pendingDials == 0
    check sender.nodePool.counters.dialFailed == 1
    check sender.nodePool.get(gate.attempts[0]).isNone
    check sender.surbCredsLen == 0
    sender.switch.dialer = gate.inner
