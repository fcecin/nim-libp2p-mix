# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results
import libp2p/[switch, stream/lpstream, peerstore, peerid]
import libp2p_mix
import libp2p_mix/[mix_protocol, serialization, delay_strategy, mix_pool]
import ../tools/[lifecycle, unittest, crypto, host_pool]
import ../utils

type SelectingMix = ref object of MixProtocol
  mode: string
  calls, credentialsAtPause: int
  paused: AsyncEvent
  selected: seq[PeerId]

type SelectingPool = ref object of HostPool
  ## Routes reply selection to the test's fake, and can fail each primitive.
  mix: SelectingMix
  failing: string

method readPeer(
    pool: SelectingPool, peerId: PeerId
): Result[MixPeerRecord, string] {.gcsafe, raises: [].} =
  if pool.failing == "read":
    return err("read failed")
  procCall readPeer(HostPool(pool), peerId)

method listPeerIds(
    pool: SelectingPool
): Result[seq[PeerId], string] {.gcsafe, raises: [].} =
  if pool.failing == "list":
    return err("list failed")
  procCall listPeerIds(HostPool(pool))

proc fakeSelectReplyPeer(
    mix: SelectingMix, excluded: seq[PeerId]
): Future[Result[PeerId, string]] {.async: (raises: [CancelledError]).} =
  mix.calls.inc()
  doAssert mix.localMixPubInfo().peerId in excluded
  if mix.mode == "excluded":
    return ok(excluded[^1])
  if mix.calls == 2:
    mix.credentialsAtPause = mix.surbCredsLen
    if mix.mode == "error":
      return err("host refused the second reply peer")
    if mix.mode == "pause":
      mix.paused.fire()
      await newAsyncEvent().wait()
  let peers = mix.pool.selectRandomNodes(1, excluded).valueOr:
    return err(error)
  let peer = peers[0]
  if mix.mode == "withdrawn":
    discard mix.hostPool.removePeer(peer.peerId)
  mix.selected.add(peer.peerId)
  return ok(peer.peerId)

method selectReplyPeer(
    pool: SelectingPool, excluded: seq[PeerId]
): Future[Result[PeerId, string]] {.async: (raises: [CancelledError]).} =
  if pool.failing == "reply":
    return err("reply selection failed")
  return await pool.mix.fakeSelectReplyPeer(excluded)

proc selectorNode(mode: string): Future[SelectingMix] {.async.} =
  let info = MixNodeInfo.generateRandom(0, rng())
  let sw = createSwitch(info.multiAddr, Opt.some(info.libp2pPrivKey))
  let mix = SelectingMix(mode: mode, paused: newAsyncEvent())
  let pool =
    SelectingPool(mix: mix, store: PeerStore.new(), allowAllAddresses: true, rng: rng())
  mix.init(
    info,
    sw,
    pool = pool,
    delayStrategy = Opt.some(DelayStrategy(NoSamplingDelayStrategy.new(rng()))),
  )
  for peer in MixNodeInfo.generateRandomMany(4, rng()):
    pool.addPeer(peer.toMixPubInfo())
  mix.registerDestReadBehavior("/test/reply-selection/1", readLp(1024))
  sw.mount(mix)
  await sw.start()
  mix.setLocalMultiAddr(sw.peerInfo.addrs[0]).expect("bound sender address")
  return mix

proc request(mix: SelectingMix): Connection =
  mix
    .toConnection(
      MixDestination.exitNode(mix.pool.listPeerIds().get()[^1]),
      "/test/reply-selection/1",
      MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(2'u8)),
    )
    .get()

proc interruptedSelection(action: string) {.async.} =
  let mix = await selectorNode("pause")
  defer:
    await stopNodes(@[mix])
  let conn = mix.request()
  defer:
    await conn.close()
  let writing = conn.writeLp(@[1'u8])
  await mix.paused.wait().wait(2.seconds)
  check:
    mix.credentialsAtPause == 1
    mix.surbCredsLen == 1
    mix.switch.connectedPeers().len == 0
  case action
  of "close":
    await conn.close().wait(2.seconds)
    expect LPStreamClosedError:
      await writing.wait(2.seconds)
  of "stop":
    await mix.stop().wait(2.seconds)
    expect LPStreamError:
      await writing.wait(2.seconds)
  else:
    await writing.cancelAndWait()
  check mix.surbCredsLen == 0
  check mix.pool.listPeerIds().get().len == 4

suite "Pool selection of the final reply peer":
  asyncTeardown:
    checkTrackers()

  asyncTest "the default selector and synchronous builder need no connected peers":
    for hostStore in [false, true]:
      let nodes = await startTestMixNodes(4, useHostStore = hostStore)
      try:
        let sender = nodes[0]
        let exitId = nodes[^1].localMixPubInfo().peerId
        let excluded = @[sender.localMixPubInfo().peerId, exitId]
        let peer = (await sender.selectReplyPeer(excluded)).get()
        check peer notin excluded
        var id: SURBIdentifier
        rng().generate(id)
        check sender.buildSurb(id, exitId, exitId).isOk
        check sender.switch.connectedPeers().len == 0
      finally:
        await stopNodes(nodes)

  asyncTest "mix rejects an excluded or withdrawn selection":
    for mode in ["excluded", "withdrawn"]:
      let mix = await selectorNode(mode)
      try:
        let conn = mix.request()
        try:
          expect LPStreamError:
            await conn.writeLp(@[1'u8]).wait(2.seconds)
          check mix.calls == 1
          check mix.surbCredsLen == 0
          check mix.switch.connectedPeers().len == 0
        finally:
          await conn.close()
      finally:
        await stopNodes(@[mix])

  asyncTest "a fixed exit that is this node is refused before any selection":
    let mix = await selectorNode("error")
    defer:
      await stopNodes(@[mix])
    # The store knows this node, so only the self check can refuse the exit.
    mix.pool.addPeer(mix.localMixPubInfo())
    let conn = mix
      .toConnection(
        MixDestination.exitNode(mix.localMixPubInfo().peerId),
        "/test/reply-selection/1",
        MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(1'u8)),
      )
      .get()
    defer:
      await conn.close()
    expect LPStreamError:
      await conn.writeLp(@[1'u8]).wait(2.seconds)
    check:
      mix.calls == 0
      mix.surbCredsLen == 0

  asyncTest "sends without replies do not invoke reply selection":
    let mix = await selectorNode("error")
    defer:
      await stopNodes(@[mix])
    let conn = mix
      .toConnection(
        MixDestination.exitNode(mix.pool.listPeerIds().get()[^1]),
        "/test/reply-selection/1",
        MixParameters(expectReply: Opt.some(false), numSurbs: Opt.some(0'u8)),
      )
      .get()
    defer:
      await conn.close()
    # The forward peers do not listen, so the send fails at the transport. It
    # calls no reply selection and registers no group.
    expect LPStreamError:
      await conn.writeLp(@[1'u8]).wait(2.seconds)
    check mix.calls == 0
    check mix.surbCredsLen == 0

  asyncTest "a later selection error releases credentials already registered":
    let mix = await selectorNode("error")
    defer:
      await stopNodes(@[mix])
    let conn = mix.request()
    defer:
      await conn.close()
    expect LPStreamError:
      await conn.writeLp(@[1'u8]).wait(2.seconds)
    check:
      mix.calls == 2
      mix.credentialsAtPause == 1
      mix.surbCredsLen == 0
      mix.pool.listPeerIds().get().len == 4
      mix.switch.connectedPeers().len == 0

  asyncTest "cancellation releases a partially built reply group":
    await interruptedSelection("cancel")

  asyncTest "entry close cancels reply selection and releases the group":
    await interruptedSelection("close")

  asyncTest "protocol stop cancels reply selection and releases the group":
    await interruptedSelection("stop")

  asyncTest "a pool error fails a send without a defect or retained credentials":
    for failing in ["list", "read", "reply"]:
      let mix = await selectorNode("error")
      try:
        let conn = mix.request()
        try:
          SelectingPool(mix.pool).failing = failing
          expect LPStreamError:
            await conn.writeLp(@[1'u8]).wait(2.seconds)
          check mix.surbCredsLen == 0
          check mix.calls == 0
        finally:
          await conn.close()
      finally:
        await stopNodes(@[mix])
