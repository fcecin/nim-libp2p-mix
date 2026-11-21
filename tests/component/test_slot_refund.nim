# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results, sequtils
import std/[importutils, tables]
import libp2p/[protocols/protocol, peerid, switch, builders, varint, dialer]
import libp2p_mix
import libp2p_mix/[exit_connection, mix_node, mix_protocol, multiaddr, serialization]
import libp2p_mix/cover_traffic
import libp2p_mix/delay_strategy
import libp2p_mix/spam_protection

import ../tools/[lifecycle, unittest, crypto]
import ../[utils, spam_protection_impl]

privateAccess(MixProtocol)

const
  TestCodec = "/mix/test/slot-refund/1.0.0"
  ReplyPayload = @[1.byte, 2, 3]

proc setupCountingNodes(
    numNodes: int
): tuple[nodes: seq[MixProtocol], spam: seq[ReclaimCountingSpamProtection]] =
  ## setupMixNodes cannot hand back the spam protection instances, and these
  ## tests need to observe what each node reclaims.
  let nodeInfos = MixNodeInfo.generateRandomMany(numNodes, rng())
  for mixNodeInfo in nodeInfos:
    let
      switch = createSwitch(mixNodeInfo.multiAddr, Opt.some(mixNodeInfo.libp2pPrivKey))
      spam = newReclaimCountingSpamProtection()
      node = MixProtocol.new(
        mixNodeInfo,
        switch,
        spamProtection = Opt.some(SpamProtection(spam)),
        delayStrategy = Opt.some(DelayStrategy(NoSamplingDelayStrategy.new(rng()))),
      )
    node.registerDestReadBehavior(TestCodec, readLp(1024))
    switch.mount(node)
    node.nodePool.add(nodeInfos.includeAllExcept(mixNodeInfo))
    result.nodes.add(node)
    result.spam.add(spam)

proc attachCover(node: MixProtocol): ConstantRateCoverTraffic =
  ## Cover is attached after the forward message so that only the packets under
  ## test consume slots. The timer stays off: epochs change when a test says so.
  result = ConstantRateCoverTraffic.new(totalSlots = 4, useInternalEpochTimer = false)
  result.onEpochChange(1)
  node.coverTraffic = Opt.some(CoverTraffic(result))

proc firstHop(nodes: seq[MixProtocol], surb: SURB): MixProtocol =
  let (peerId, _) = surb.hop.get().bytesToMultiAddr().expect("valid SURB hop")
  nodes.filterIt(it.switch.peerInfo.peerId == peerId)[0]

proc readUntilEnd(conn: Connection) {.async: (raises: [CancelledError]).} =
  ## Reads `conn` until it ends, as MixProtocol does for a hop stream that it
  ## dials. Without a read, libp2p 2.5 leaves the protocol acknowledgement on
  ## the stream, and the mplex connection then does not see its peer stop.
  var buf: array[64, byte]
  try:
    while not conn.atEof:
      discard await conn.readOnce(addr buf[0], buf.len)
  except LPStreamError:
    return

proc requestSurb(
    nodes: seq[MixProtocol]
): Future[tuple[surb: SURB, conn: Connection]] {.async.} =
  ## Starts the nodes and sends one request from the first node to the last,
  ## returning the SURB that the last node received with it.
  let surbs = newAsyncQueue[SURB]()
  nodes[^1].switch.mount(
    LPProtocol.new(
      codecs = @[TestCodec],
      handler = proc(
          conn: Connection, proto: string
      ) {.async: (raises: [CancelledError]).} =
        try:
          discard await conn.readLp(1024)
          await surbs.put(MixExitConnection(conn).takeSURBs()[0])
        except LPStreamError as exc:
          raiseAssert exc.msg
      ,
    )
  )
  await startNodes(nodes)

  let conn = nodes[0]
    .toConnection(
      MixDestination.exitNode(nodes[^1].switch.peerInfo.peerId),
      TestCodec,
      MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(byte(1))),
    )
    .expect("could not build connection")
  await conn.writeLp(@[1.byte])
  return (await surbs.get().wait(5.seconds), conn)

suite "Slot refund - SURB reply":
  asyncTeardown:
    checkTrackers()

  asyncTest "failed first dial refunds the slot and reclaims the proof":
    let (nodes, spam) = setupCountingNodes(10)
    let (surb, conn) = await nodes.requestSurb()
    defer:
      await conn.close()
      await stopNodes(nodes)
    let ct = nodes[^1].attachCover()

    await nodes.firstHop(surb).switch.stop()
    let reclaimedBefore = spam[^1].reclaimCount

    check (await nodes[^1].sendSurbReply(surb, ReplyPayload)).isErr
    check ct.slotPool.nonCoverClaimed == 0
    check spam[^1].reclaimCount == reclaimedBefore + 1

  asyncTest "reply over a stream that the next hop closed refunds the slot and the proof":
    ## A send does not write to a stream that its next hop closed. It dials
    ## again, so a failed dial refunds the packet.
    let (nodes, spam) = setupCountingNodes(10)
    let (surb, conn) = await nodes.requestSurb()
    defer:
      await conn.close()
      await stopNodes(nodes)
    let ct = nodes[^1].attachCover()

    # A successful reply caches a stream to the first hop. The first hop then
    # stops, and the replying node sees the end of that stream.
    check (await nodes[^1].sendSurbReply(surb, ReplyPayload)).isOk
    let firstHop = nodes.firstHop(surb)
    let cached = nodes[^1].connPool.getOrDefault(firstHop.switch.peerInfo.peerId)
    check not cached.isNil
    await firstHop.switch.stop()
    checkUntilTimeout:
      cached.atEof or cached.closed
    let reclaimedBefore = spam[^1].reclaimCount

    check (await nodes[^1].sendSurbReply(surb, ReplyPayload)).isErr
    check ct.slotPool.nonCoverClaimed == 1
    check spam[^1].reclaimCount == reclaimedBefore + 1

  asyncTest "failed reply claimed in an earlier epoch leaves the new epoch alone":
    let (nodes, _) = setupCountingNodes(10)
    let (surb, conn) = await nodes.requestSurb()
    defer:
      await conn.close()
      await stopNodes(nodes)
    let ct = nodes[^1].attachCover()

    await nodes.firstHop(surb).switch.stop()

    let reply = nodes[^1].sendSurbReply(surb, ReplyPayload)
    check ct.slotPool.nonCoverClaimed == 1

    ct.onEpochChange(2)
    discard ct.slotPool.claimSlot()

    check (await reply).isErr
    check ct.slotPool.nonCoverClaimed == 1

proc sendToExit(nodes: seq[MixProtocol]) {.async.} =
  ## With 5 nodes the path is two of nodes[1 .. 3] in random order, then the
  ## exit nodes[4], so the second of those two forwards to the exit.
  let res = await nodes[0].anonymizeLocalProtocolSend(
    newAsyncQueue[seq[byte]](),
    @[1.byte],
    TestCodec,
    MixDestination.exitNode(nodes[4].switch.peerInfo.peerId),
    0,
  )
  check res.isOk

suite "Slot refund - forward":
  asyncTeardown:
    checkTrackers()

  asyncTest "failed first dial refunds the slot and reclaims the proof":
    let (nodes, spam) = setupCountingNodes(5)
    await startNodes(nodes)
    defer:
      await stopNodes(nodes)
    let hops = nodes[1 .. 3].mapIt(it.attachCover())

    await nodes[4].switch.stop()
    await nodes.sendToExit()
    checkUntilTimeoutCustom(5.seconds, 10.milliseconds):
      spam[1 .. 3].mapIt(it.reclaimCount).foldl(a + b) == 1

    # The first hop's forward went out; the second hop's dial failed
    check hops.mapIt(it.slotPool.nonCoverClaimed).foldl(a + b) == 1

  asyncTest "forward over a stream that the next hop closed refunds the slot and the proof":
    ## The last relay does not write to its stream that the exit closed. Its
    ## dial of the exit fails, so its packet gets a refund. The first relay
    ## keeps the slot and the proof of its forward.
    let (nodes, spam) = setupCountingNodes(5)
    await startNodes(nodes)
    defer:
      await stopNodes(nodes)

    # Establish every possible second hop's cached stream directly. Random
    # warm-up messages can still be in flight when accounting is enabled.
    let exitPeer = nodes[4].switch.peerInfo.peerId
    var readers: seq[Future[void]]
    for node in nodes[1 .. 3]:
      let conn = await node.switch.dial(
        exitPeer,
        @[nodes[4].localMixPubInfo().expect("local mix info").multiAddr],
        @[MixProtocolID],
      )
      node.connPool[exitPeer] = conn
      readers.add(conn.readUntilEnd())

    let hops = nodes[1 .. 3].mapIt(it.attachCover())
    await nodes[4].switch.stop()
    checkUntilTimeoutCustom(5.seconds, 10.milliseconds):
      nodes[1 .. 3].allIt(it.connPool[exitPeer].closed())
    await allFutures(readers)

    await nodes.sendToExit()
    # Proof generation shows both relays received the packet; then wait for
    # their owned forwarding tasks to finish before checking final accounting.
    checkUntilTimeoutCustom(5.seconds, 10.milliseconds):
      spam[1 .. 3].mapIt(it.generateCount).foldl(a + b) == 2
      nodes[1 .. 3].allIt(it.ongoingMixMessages.len == 0)

    check hops.mapIt(it.slotPool.nonCoverClaimed).foldl(a + b) == 1
    check spam[1 .. 3].mapIt(it.reclaimCount).foldl(a + b) == 1

suite "Slot refund - local send":
  asyncTeardown:
    checkTrackers()

  asyncTest "failed first dial refunds the slot and reclaims the proof":
    let (nodes, spam) = setupCountingNodes(10)
    await startNodes(nodes)
    defer:
      await stopNodes(nodes)
    let ct = nodes[0].attachCover()

    # Every candidate first hop is down, whichever path gets selected
    for node in nodes[1 ..^ 1]:
      await node.switch.stop()

    let res = await nodes[0].anonymizeLocalProtocolSend(
      newAsyncQueue[seq[byte]](), @[1.byte], TestCodec, nodes[^1].toMixDestination(), 0
    )

    check res.isErr
    check ct.slotPool.nonCoverClaimed == 0
    # Proves the send got as far as a proof, so the slot was claimed and refunded
    check spam[0].reclaimCount == 1

  asyncTest "failed send claimed in an earlier epoch leaves the new epoch alone":
    let (nodes, _) = setupCountingNodes(10)
    await startNodes(nodes)
    defer:
      await stopNodes(nodes)
    let ct = nodes[0].attachCover()

    for node in nodes[1 ..^ 1]:
      await node.switch.stop()

    let send = nodes[0].anonymizeLocalProtocolSend(
      newAsyncQueue[seq[byte]](), @[1.byte], TestCodec, nodes[^1].toMixDestination(), 0
    )
    check ct.slotPool.nonCoverClaimed == 1

    ct.onEpochChange(2)
    discard ct.slotPool.claimSlot()

    check (await send).isErr
    check ct.slotPool.nonCoverClaimed == 1

type
  FakeSpamProtection = ref object of ReclaimCountingSpamProtection
    ## Counts its proofs, gives each one its own token and keeps the tokens that
    ## Mix reclaims. With `finish` set, a proof starts and waits for that event.
    generated: int
    reclaimed: seq[seq[byte]]
    finish: AsyncEvent
    started: bool
    failing: bool
    failures: int
    wrongSize: bool
    coverAtSend: bool

  FailingStream = ref object of Connection
    ## A stream whose writes and reads fail, as on a closed stream.

  FailingDialer = ref object of Dialer
    ## Opens a FailingStream for every dial, with no connection.

method generateProofAsync(
    self: FakeSpamProtection, bindingData: seq[byte]
): Future[Result[ProofResult, string]] {.async: (raises: [CancelledError]).} =
  if not self.finish.isNil:
    self.started = true
    await self.finish.wait()
  if self.failing:
    inc self.failures
    return err("no proof")
  inc self.generated
  let size = self.proofSize + ord(self.wrongSize)
  return ok(ProofResult(proof: newSeq[byte](size), token: @[byte(self.generated)]))

method reclaimProofToken(
    self: FakeSpamProtection, token: seq[byte]
) {.gcsafe, raises: [].} =
  self.reclaimed.add(token)
  inc self.reclaimCount

method precomputeCoverProofs(self: FakeSpamProtection): bool {.gcsafe, raises: [].} =
  not self.coverAtSend

method write(
    self: FailingStream, msg: sink seq[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError]).} =
  raise newLPStreamClosedError()

method readOnce(
    self: FailingStream, pbytes: pointer, nbytes: int
): Future[int] {.async: (raises: [CancelledError, LPStreamError]).} =
  raise newLPStreamClosedError()

method dial(
    self: FailingDialer,
    peerId: PeerId,
    addrs: seq[MultiAddress],
    protos: seq[string],
    forceDial = false,
): Future[Stream] {.async: (raises: [DialFailedError, CancelledError]).} =
  let stream = FailingStream(peerId: peerId, dir: Direction.Out)
  stream.initStream()
  return stream

const LongWait = Delay(60_000)

proc setupNodes(
    numNodes: int, withSpam = true, withCover = false
): tuple[
  nodes: seq[MixProtocol],
  spam: seq[FakeSpamProtection],
  delays: seq[FixedDelayStrategy],
] =
  ## Like setupCountingNodes, but the test controls the proofs and the wait.
  ## With `withCover`, the first node gets cover traffic through `MixProtocol.new`.
  let nodeInfos = MixNodeInfo.generateRandomMany(numNodes, rng())
  var
    nodes = newSeq[MixProtocol]()
    providers = newSeq[FakeSpamProtection]()
    delays = newSeq[FixedDelayStrategy]()
  for i, mixNodeInfo in nodeInfos:
    let
      switch = createSwitch(mixNodeInfo.multiAddr, Opt.some(mixNodeInfo.libp2pPrivKey))
      spam = FakeSpamProtection(proofSize: newReclaimCountingSpamProtection().proofSize)
      delay = FixedDelayStrategy()
      cover =
        if withCover and i == 0:
          Opt.some(
            CoverTraffic(
              ConstantRateCoverTraffic.new(
                totalSlots = 4, useInternalEpochTimer = false
              )
            )
          )
        else:
          Opt.none(CoverTraffic)
      node = MixProtocol.new(
        mixNodeInfo,
        switch,
        spamProtection =
          if withSpam:
            Opt.some(SpamProtection(spam))
          else:
            Opt.none(SpamProtection),
        delayStrategy = Opt.some(DelayStrategy(delay)),
        coverTraffic = cover,
      )
    node.registerDestReadBehavior(TestCodec, readLp(1024))
    switch.mount(node)
    node.nodePool.add(nodeInfos.includeAllExcept(mixNodeInfo))
    nodes.add(node)
    providers.add(spam)
    delays.add(delay)
  (nodes, providers, delays)

proc peerId(node: MixProtocol): PeerId =
  node.switch.peerInfo.peerId

proc sendToLast(nodes: seq[MixProtocol]): Future[Result[Opt[SurbSession], string]] =
  ## A send from the first node to the last, over the three middle nodes in
  ## random order.
  nodes[0].anonymizeLocalProtocolSend(
    newAsyncQueue[seq[byte]](), @[1.byte], TestCodec, nodes[^1].toMixDestination(), 0
  )

proc breakCachedStreams(nodes, hops: seq[MixProtocol]) {.async.} =
  ## Gives every node a cached stream to each of `hops` and then closes the
  ## connections, so the next write to any of these streams fails.
  for node in nodes:
    for hop in hops.filterIt(it != node):
      let sent =
        await node.sendCoverPacket(hop.peerId, hop.switch.peerInfo.addrs[0], @[1.byte])
      check sent.isOk
  for node in nodes:
    for hop in hops.filterIt(it != node):
      await node.switch.disconnect(hop.peerId)

proc redirectHops(node: MixProtocol, hops: seq[MixProtocol], server: HoldingServer) =
  ## Makes `node` dial `server` in place of every one of `hops`.
  for hop in hops:
    node.switch.peerStore[AddressBook][hop.peerId] = @[server.address()]
    node.switch.peerStore[LastSeenOutboundBook][hop.peerId] = Opt.some(server.address())

proc failWrites(node: MixProtocol) =
  ## Makes every write of `node` to a hop fail. The node opens a new stream
  ## after the first failure, and the write to that stream fails too.
  let switch = node.switch
  switch.dialer = FailingDialer.new(
    switch.peerInfo.peerId, switch.connManager, switch.peerStore, switch.transports,
    switch.ms,
  )

proc redirectForwards(nodes: seq[MixProtocol], server: HoldingServer) {.async.} =
  ## Makes the first hop of `sendToLast` dial `server` for the hop after it. The
  ## sender reaches its first hop over an open connection, and its packet gives
  ## the address of `server` for the other hops.
  for hop in nodes[1 .. 3]:
    await nodes[0].switch.connect(hop.peerId, hop.switch.peerInfo.addrs)
  nodes[0].redirectHops(nodes[1 .. 3], server)

suite "Slot refund - packet stages":
  asyncTeardown:
    checkTrackers()

  asyncTest "send cancelled in wait refunds one slot and reclaims one proof":
    let (nodes, spam, delays) = setupNodes(5)
    startAndDeferStop(nodes)
    let ct = nodes[0].attachCover()
    delays[0].delay = LongWait

    let kept = nodes.sendToLast()
    let cancelled = nodes.sendToLast()
    checkUntilTimeout:
      spam[0].generated == 2
    check ct.slotPool.nonCoverClaimed == 2

    await cancelled.cancelAndWait()
    check:
      ct.slotPool.nonCoverClaimed == 1
      spam[0].reclaimed == @[@[2.byte]]
    await kept.cancelAndWait()

  asyncTest "send cancelled during proof generation keeps slot":
    ## The provider may have used the message ID of a proof that it did not
    ## finish, so the slot stays claimed.
    let (nodes, spam, _) = setupNodes(5)
    startAndDeferStop(nodes)
    let ct = nodes[0].attachCover()
    spam[0].finish = newAsyncEvent()

    let send = nodes.sendToLast()
    checkUntilTimeout:
      spam[0].started
    check ct.slotPool.nonCoverClaimed == 1

    await send.cancelAndWait()
    check:
      ct.slotPool.nonCoverClaimed == 1
      spam[0].reclaimCount == 0

  asyncTest "send cancelled as proof finishes refunds slot and reclaims proof":
    let (nodes, spam, delays) = setupNodes(5)
    startAndDeferStop(nodes)
    let ct = nodes[0].attachCover()
    delays[0].delay = LongWait
    spam[0].finish = newAsyncEvent()

    let send = nodes.sendToLast()
    checkUntilTimeout:
      spam[0].started

    # The provider finishes the proof, and the cancel comes before the send
    # sees it.
    spam[0].finish.fire()
    await send.cancelAndWait()
    check:
      spam[0].generated == 1
      ct.slotPool.nonCoverClaimed == 0
      spam[0].reclaimCount == 1

  asyncTest "send cancelled after failed proof refunds slot":
    let (nodes, spam, delays) = setupNodes(5)
    startAndDeferStop(nodes)
    let ct = nodes[0].attachCover()
    delays[0].delay = LongWait
    spam[0].failing = true

    let send = nodes.sendToLast()
    checkUntilTimeout:
      spam[0].failures == 1
    check ct.slotPool.nonCoverClaimed == 1

    await send.cancelAndWait()
    check:
      ct.slotPool.nonCoverClaimed == 0
      spam[0].reclaimCount == 0

  asyncTest "send cancelled without spam protection refunds slot":
    let (nodes, _, delays) = setupNodes(5, withSpam = false)
    startAndDeferStop(nodes)
    let ct = nodes[0].attachCover()
    delays[0].delay = LongWait

    let send = nodes.sendToLast()
    check ct.slotPool.nonCoverClaimed == 1

    await send.cancelAndWait()
    check ct.slotPool.nonCoverClaimed == 0

  asyncTest "send cancelled without cover traffic reclaims proof":
    let (nodes, spam, delays) = setupNodes(5)
    startAndDeferStop(nodes)
    delays[0].delay = LongWait

    let send = nodes.sendToLast()
    checkUntilTimeout:
      spam[0].generated == 1

    await send.cancelAndWait()
    check spam[0].reclaimCount == 1

  asyncTest "send cancelled after epoch change reclaims proof, refunds no slot":
    let (nodes, spam, delays) = setupNodes(5)
    startAndDeferStop(nodes)
    let ct = nodes[0].attachCover()
    delays[0].delay = LongWait

    let send = nodes.sendToLast()
    checkUntilTimeout:
      spam[0].generated == 1

    ct.onEpochChange(2)
    discard ct.slotPool.claimSlot()

    await send.cancelAndWait()
    check:
      ct.slotPool.nonCoverClaimed == 1
      spam[0].reclaimCount == 1

  asyncTest "send with failed proof refunds slot":
    let (nodes, spam, _) = setupNodes(5)
    startAndDeferStop(nodes)
    let ct = nodes[0].attachCover()
    spam[0].failing = true

    let sent = await nodes.sendToLast()
    check:
      sent.isErr
      spam[0].failures == 1
      ct.slotPool.nonCoverClaimed == 0
      spam[0].reclaimCount == 0

  asyncTest "send with wrong proof size refunds slot and reclaims proof":
    let (nodes, spam, _) = setupNodes(5)
    startAndDeferStop(nodes)
    let ct = nodes[0].attachCover()
    spam[0].wrongSize = true

    let sent = await nodes.sendToLast()
    check:
      sent.isErr
      ct.slotPool.nonCoverClaimed == 0
      spam[0].reclaimCount == 1

  asyncTest "send cancelled in dial refunds slot and reclaims proof":
    let (nodes, spam, _) = setupNodes(5)
    startAndDeferStop(nodes)
    let server = HoldingServer.new()
    defer:
      await server.close()
    nodes[0].redirectHops(nodes[1 .. 3], server)
    let ct = nodes[0].attachCover()
    let errorsBefore = errorCount("Entry", "SEND_FAILED")

    let send = nodes.sendToLast()
    checkUntilTimeout:
      server.connections.len == 1
    check ct.slotPool.nonCoverClaimed == 1

    await send.cancelAndWait()
    check:
      errorCount("Entry", "SEND_FAILED") == errorsBefore
      ct.slotPool.nonCoverClaimed == 0
      spam[0].reclaimCount == 1

  asyncTest "send with failed dial refunds one slot and reclaims one proof":
    let (nodes, spam, delays) = setupNodes(5)
    startAndDeferStop(nodes)
    # A closed server refuses the dial.
    let server = HoldingServer.new()
    nodes[0].redirectHops(nodes[1 .. 3], server)
    await server.close()
    let ct = nodes[0].attachCover()
    delays[0].delay = LongWait

    let kept = nodes.sendToLast()
    delays[0].delay = NoDelay
    check:
      (await nodes.sendToLast()).isErr
      ct.slotPool.nonCoverClaimed == 1
      spam[0].reclaimed == @[@[2.byte]]
    await kept.cancelAndWait()

  asyncTest "send cancelled in redial of a closed stream refunds slot and reclaims proof":
    ## A send does not write to a stream that its next hop closed, so a cancel
    ## in the dial that replaces the stream refunds the packet.
    let (nodes, spam, _) = setupNodes(5)
    startAndDeferStop(nodes)
    let server = HoldingServer.new()
    defer:
      await server.close()
    await breakCachedStreams(@[nodes[0]], nodes[1 .. 3])
    nodes[0].redirectHops(nodes[1 .. 3], server)
    let ct = nodes[0].attachCover()

    let send = nodes.sendToLast()
    checkUntilTimeout:
      server.connections.len == 1
    check ct.slotPool.nonCoverClaimed == 1

    await send.cancelAndWait()
    check:
      ct.slotPool.nonCoverClaimed == 0
      spam[0].reclaimCount == 1

  asyncTest "send cancelled in retry after failed write keeps slot and proof":
    ## The first hop may have a part of the packet whose write failed, so a
    ## cancel in the retry refunds nothing.
    let (nodes, spam, _) = setupNodes(5)
    startAndDeferStop(nodes)
    let dialer = await nodes[0].holdHopStreams(nodes[1 .. 3])
    dialer.holdWrites = true
    let ct = nodes[0].attachCover()

    let send = nodes.sendToLast()
    checkUntilTimeout:
      dialer.firstHeld()
    let held = dialer.streams[0]

    # The write fails, and the retry waits for the reset of the failed stream.
    held.closing = Future[void].Raising([CancelledError]).init("HoldingStream.closing")
    held.failWrites(newLPStreamResetError())
    checkUntilTimeout:
      held.isClosed
    send.cancelSoon()
    check await send.join().withTimeout(1.seconds)
    held.closing.complete()
    check:
      ct.slotPool.nonCoverClaimed == 1
      spam[0].reclaimCount == 0

  asyncTest "send with failed write keeps slot and proof":
    let (nodes, spam, _) = setupNodes(5)
    startAndDeferStop(nodes)
    nodes[0].failWrites()
    let ct = nodes[0].attachCover()

    check:
      (await nodes.sendToLast()).isErr
      ct.slotPool.nonCoverClaimed == 1
      spam[0].reclaimCount == 0

  asyncTest "reply with failed write keeps slot and proof":
    let (nodes, spam, _) = setupNodes(5)
    startAndDeferStop(nodes)
    let exitPeerId = nodes[^1].switch.peerInfo.peerId
    let surb = nodes[0]
      .buildSurb(rng().generate(SURBIdentifier), exitPeerId, exitPeerId)
      .expect("SURB").surb
    nodes[^1].failWrites()
    let ct = nodes[^1].attachCover()

    check:
      (await nodes[^1].sendSurbReply(surb, ReplyPayload)).isErr
      ct.slotPool.nonCoverClaimed == 1
      spam[^1].reclaimCount == 0

  asyncTest "send cancelled behind held write refunds slot and reclaims proof":
    let (nodes, spam, _) = setupNodes(5)
    startAndDeferStop(nodes)
    let dialer = await nodes[0].holdHopStreams(nodes[1 .. 3])
    dialer.holdWrites = true
    # A held cover write to each middle node makes the send wait behind one of
    # them, at any first hop.
    let covers = nodes[1 .. 3].mapIt(
      nodes[0].sendCoverPacket(it.peerId, it.switch.peerInfo.addrs[0], @[1.byte])
    )
    checkUntilTimeout:
      dialer.streams.len == 3
      dialer.streams.allIt(it.pendingWrites.len == 1)
    let ct = nodes[0].attachCover()

    let send = nodes.sendToLast()
    checkUntilTimeout:
      dialer.streams.anyIt(nodes[0].waitingWrites(it) == 1)
    check ct.slotPool.nonCoverClaimed == 1

    await send.cancelAndWait()
    check:
      ct.slotPool.nonCoverClaimed == 0
      spam[0].reclaimCount == 1
      dialer.streams.allIt(it.pendingWrites.len == 1)

    for stream in dialer.streams:
      stream.release()
    await allFutures(covers).wait(2.seconds)
    check dialer.streams.allIt(it.written.len == 1)

  asyncTest "send cancelled as its turn comes writes its packet and keeps slot and proof":
    let (nodes, spam, _) = setupNodes(5)
    startAndDeferStop(nodes)
    let dialer = await nodes[0].holdHopStreams(nodes[1 .. 3])
    dialer.holdWrites = true
    let heldCovers = nodes[1 .. 3].mapIt(
      nodes[0].sendCoverPacket(it.peerId, it.switch.peerInfo.addrs[0], @[1.byte])
    )
    checkUntilTimeout:
      dialer.streams.len == 3
      dialer.streams.allIt(it.pendingWrites.len == 1)
    let ct = nodes[0].attachCover()

    let send = nodes.sendToLast()
    checkUntilTimeout:
      dialer.streams.anyIt(nodes[0].waitingWrites(it) == 1)
    let held = dialer.streams.filterIt(nodes[0].waitingWrites(it) == 1)[0]

    # The cancel comes in the turn where the write before the send ends. The
    # send gets the stream first, and the cancel then stops only its wait.
    nodes[0].hopWrites[Connection(held)].addCallback(
      proc(_: pointer) {.gcsafe, raises: [].} =
        send.cancelSoon()
    )
    held.release()
    check await send.join().withTimeout(2.seconds)
    check:
      send.cancelled
      held.pendingWrites.len == 1
      ct.slotPool.nonCoverClaimed == 1
      spam[0].reclaimCount == 0

    held.release()
    checkUntilTimeout:
      held.written.len == 2
    check heldCovers.allIt(not it.failed)

  asyncTest "send cancelled in held write keeps slot and proof":
    let (nodes, spam, _) = setupNodes(5)
    startAndDeferStop(nodes)
    let dialer = await nodes[0].holdHopStreams(nodes[1 .. 3])
    dialer.holdWrites = true
    let ct = nodes[0].attachCover()

    let send = nodes.sendToLast()
    checkUntilTimeout:
      dialer.firstHeld()
    check ct.slotPool.nonCoverClaimed == 1

    await send.cancelAndWait()
    check:
      ct.slotPool.nonCoverClaimed == 1
      spam[0].reclaimCount == 0

    let held = dialer.streams[0]
    held.release()
    checkUntilTimeout:
      held.written.len == 1

  asyncTest "forward stopped in held write keeps slot and proof":
    let (nodes, spam, _) = setupNodes(5)
    startAndDeferStop(nodes)
    let covers = nodes[1 .. 3].mapIt(it.attachCover())
    var dialers: seq[HoldingDialer]
    for hop in nodes[1 .. 3]:
      let dialer = await hop.holdHopStreams(nodes[1 ..^ 1].filterIt(it != hop))
      dialer.holdWrites = true
      dialers.add(dialer)

    check (await nodes.sendToLast()).isOk
    checkUntilTimeout:
      dialers.anyIt(it.firstHeld())
    check covers.mapIt(it.slotPool.nonCoverClaimed).foldl(a + b) == 1

    for hop in nodes[1 .. 3]:
      let stopping = hop.stop()
      check await stopping.join().withTimeout(2.seconds)
    check:
      covers.mapIt(it.slotPool.nonCoverClaimed).foldl(a + b) == 1
      spam[1 .. 3].mapIt(it.reclaimCount).foldl(a + b) == 0
      dialers.anyIt(it.streams.anyIt(it.cancelledWrites == 1 and it.isClosed))

  asyncTest "forward cancelled in held write finishes its packet and keeps slot and proof":
    let (nodes, spam, _) = setupNodes(5)
    startAndDeferStop(nodes)
    let covers = nodes[1 .. 3].mapIt(it.attachCover())
    var dialers: seq[HoldingDialer]
    for hop in nodes[1 .. 3]:
      let dialer = await hop.holdHopStreams(nodes[1 ..^ 1].filterIt(it != hop))
      dialer.holdWrites = true
      dialers.add(dialer)

    check (await nodes.sendToLast()).isOk
    checkUntilTimeout:
      dialers.anyIt(it.firstHeld())
    let index = toSeq(0 ..< dialers.len).filterIt(dialers[it].firstHeld())[0]
    let relay = nodes[1 + index]
    let held = dialers[index].streams[0]

    # The relay keeps running, and only the task of the forward ends.
    for handler in relay.ongoingMixMessages.values:
      handler.cancelSoon()
    checkUntilTimeout:
      relay.ongoingMixMessages.len == 0
    check held.pendingWrites.len == 1

    held.release()
    checkUntilTimeout:
      held.written.len == 1
    check:
      held.cancelledWrites == 0
      covers.mapIt(it.slotPool.nonCoverClaimed).foldl(a + b) == 1
      spam[1 .. 3].mapIt(it.reclaimCount).foldl(a + b) == 0

  asyncTest "send at stalled stream refunds slot and reclaims proof":
    let (nodes, spam, _) = setupNodes(5)
    startAndDeferStop(nodes)
    let dialer = await nodes[0].holdHopStreams(nodes[1 .. 3])
    dialer.holdWrites = true
    # Each middle node gets a held cover write and a full line of writes behind
    # it, so the send finds a stalled stream at any first hop.
    let heldCovers = nodes[1 .. 3].mapIt(
      nodes[0].sendCoverPacket(it.peerId, it.switch.peerInfo.addrs[0], @[1.byte])
    )
    checkUntilTimeout:
      dialer.streams.len == 3
      dialer.streams.allIt(it.pendingWrites.len == 1)
    # The length prefix of a 4096-byte packet takes 2 bytes.
    let packet = newSeq[byte](4096)
    let fit = WaitingBytesLimit div (packet.len + 2)
    var waiting: seq[typeof(heldCovers[0])]
    for hop in nodes[1 .. 3]:
      for _ in 1 .. fit:
        waiting.add(
          nodes[0].sendCoverPacket(hop.peerId, hop.switch.peerInfo.addrs[0], packet)
        )
    check dialer.streams.allIt(nodes[0].waitingWrites(it) == fit)
    for stream in dialer.streams:
      nodes[0].ageHopGate(stream)
    let ct = nodes[0].attachCover()

    let sent = await nodes.sendToLast().wait(5.seconds)
    check:
      sent.isErr
      ct.slotPool.nonCoverClaimed == 0
      spam[0].reclaimCount == 1

  asyncTest "reply cancelled in wait refunds slot and reclaims proof":
    let (nodes, spam, delays) = setupNodes(5)
    startAndDeferStop(nodes)
    let exitPeerId = nodes[^1].switch.peerInfo.peerId
    let surb = nodes[0]
      .buildSurb(rng().generate(SURBIdentifier), exitPeerId, exitPeerId)
      .expect("SURB").surb
    let ct = nodes[^1].attachCover()
    delays[^1].delay = LongWait

    let reply = nodes[^1].sendSurbReply(surb, ReplyPayload)
    checkUntilTimeout:
      spam[^1].generated == 1
    check ct.slotPool.nonCoverClaimed == 1

    await reply.cancelAndWait()
    check:
      ct.slotPool.nonCoverClaimed == 0
      spam[^1].reclaimCount == 1

  asyncTest "forward stopped in wait refunds slot and reclaims proof":
    let (nodes, spam, delays) = setupNodes(5)
    startAndDeferStop(nodes)
    let covers = nodes[1 .. 3].mapIt(it.attachCover())
    for strategy in delays[1 .. 3]:
      strategy.delay = LongWait

    check (await nodes.sendToLast()).isOk
    checkUntilTimeout:
      spam[1 .. 3].mapIt(it.generated).foldl(a + b) == 1
    check covers.mapIt(it.slotPool.nonCoverClaimed).foldl(a + b) == 1

    for hop in nodes[1 .. 3]:
      await hop.stop()
    check:
      covers.mapIt(it.slotPool.nonCoverClaimed).foldl(a + b) == 0
      spam[1 .. 3].mapIt(it.reclaimCount).foldl(a + b) == 1

  asyncTest "cover packet without spam protection cancelled in wait returns slot":
    let (nodes, _, delays) = setupNodes(5, withSpam = false, withCover = true)
    let ct = ConstantRateCoverTraffic(nodes[0].coverTraffic.get())
    ct.onEpochChange(1)
    delays[0].delay = LongWait

    let emission = ct.emitCoverPacket()
    checkUntilTimeout:
      ct.slotPool.coverClaimed == 1

    await emission.cancelAndWait()
    check ct.slotPool.coverClaimed == 0

  asyncTest "forward stopped in wait after failed proof refunds slot":
    let (nodes, spam, delays) = setupNodes(5)
    startAndDeferStop(nodes)
    let covers = nodes[1 .. 3].mapIt(it.attachCover())
    for strategy in delays[1 .. 3]:
      strategy.delay = LongWait
    for provider in spam[1 .. 3]:
      provider.failing = true

    check (await nodes.sendToLast()).isOk
    checkUntilTimeout:
      spam[1 .. 3].mapIt(it.failures).foldl(a + b) == 1
    check covers.mapIt(it.slotPool.nonCoverClaimed).foldl(a + b) == 1

    for hop in nodes[1 .. 3]:
      await hop.stop()
    check:
      covers.mapIt(it.slotPool.nonCoverClaimed).foldl(a + b) == 0
      spam[1 .. 3].mapIt(it.reclaimCount).foldl(a + b) == 0

  asyncTest "forward with wrong proof size refunds slot and reclaims proof":
    let (nodes, spam, _) = setupNodes(5)
    startAndDeferStop(nodes)
    let covers = nodes[1 .. 3].mapIt(it.attachCover())
    for provider in spam[1 .. 3]:
      provider.wrongSize = true

    check (await nodes.sendToLast()).isOk
    checkUntilTimeout:
      spam[1 .. 3].mapIt(it.reclaimCount).foldl(a + b) == 1
      covers.mapIt(it.slotPool.nonCoverClaimed).foldl(a + b) == 0
    check spam[1 .. 3].mapIt(it.generated).foldl(a + b) == 1

  asyncTest "cover packet proved at send cancelled in wait returns slot and reclaims token":
    let (nodes, spam, delays) = setupNodes(5, withCover = true)
    let ct = ConstantRateCoverTraffic(nodes[0].coverTraffic.get())
    ct.onEpochChange(1)
    spam[0].coverAtSend = true
    delays[0].delay = LongWait

    let emission = ct.emitCoverPacket()
    checkUntilTimeout:
      spam[0].generated == 1
    check ct.slotPool.coverClaimed == 1

    await emission.cancelAndWait()
    check:
      spam[0].reclaimed == @[@[1.byte]]
      ct.slotPool.coverClaimed == 0

  asyncTest "forward stopped during proof generation keeps slot":
    let (nodes, spam, delays) = setupNodes(5)
    startAndDeferStop(nodes)
    let covers = nodes[1 .. 3].mapIt(it.attachCover())
    for i in 1 .. 3:
      delays[i].delay = LongWait
      spam[i].finish = newAsyncEvent()

    check (await nodes.sendToLast()).isOk
    checkUntilTimeout:
      spam[1 .. 3].anyIt(it.started)
    check covers.mapIt(it.slotPool.nonCoverClaimed).foldl(a + b) == 1

    for hop in nodes[1 .. 3]:
      await hop.stop()
    check:
      covers.mapIt(it.slotPool.nonCoverClaimed).foldl(a + b) == 1
      spam[1 .. 3].mapIt(it.reclaimCount).foldl(a + b) == 0

  asyncTest "forward with failed proof refunds slot":
    let (nodes, spam, _) = setupNodes(5)
    startAndDeferStop(nodes)
    let covers = nodes[1 .. 3].mapIt(it.attachCover())
    for provider in spam[1 .. 3]:
      provider.failing = true

    check (await nodes.sendToLast()).isOk
    checkUntilTimeout:
      spam[1 .. 3].mapIt(it.failures).foldl(a + b) == 1
    checkUntilTimeout:
      covers.mapIt(it.slotPool.nonCoverClaimed).foldl(a + b) == 0
    check spam[1 .. 3].mapIt(it.reclaimCount).foldl(a + b) == 0

  asyncTest "forward with failed dial refunds slot and reclaims proof":
    let (nodes, spam, _) = setupNodes(5)
    startAndDeferStop(nodes)
    # A closed server refuses the dial.
    let server = HoldingServer.new()
    await nodes.redirectForwards(server)
    await server.close()
    let covers = nodes[1 .. 3].mapIt(it.attachCover())

    check (await nodes.sendToLast()).isOk
    checkUntilTimeout:
      spam[1 .. 3].mapIt(it.reclaimCount).foldl(a + b) == 1
    check covers.mapIt(it.slotPool.nonCoverClaimed).foldl(a + b) == 0

  asyncTest "forward stopped in dial refunds slot and reclaims proof":
    let (nodes, spam, _) = setupNodes(5)
    startAndDeferStop(nodes)
    let server = HoldingServer.new()
    defer:
      await server.close()
    await nodes.redirectForwards(server)
    let covers = nodes[1 .. 3].mapIt(it.attachCover())

    check (await nodes.sendToLast()).isOk
    checkUntilTimeout:
      server.connections.len == 1

    for hop in nodes[1 .. 3]:
      await hop.stop()
    check:
      covers.mapIt(it.slotPool.nonCoverClaimed).foldl(a + b) == 0
      spam[1 .. 3].mapIt(it.reclaimCount).foldl(a + b) == 1

  asyncTest "forward stopped in redial of a closed stream refunds slot and reclaims proof":
    let (nodes, spam, _) = setupNodes(5)
    startAndDeferStop(nodes)
    let server = HoldingServer.new()
    defer:
      await server.close()
    await breakCachedStreams(nodes[1 .. 3], nodes[1 .. 3])
    await nodes.redirectForwards(server)
    let covers = nodes[1 .. 3].mapIt(it.attachCover())

    check (await nodes.sendToLast()).isOk
    checkUntilTimeout:
      server.connections.len == 1

    for hop in nodes[1 .. 3]:
      await hop.stop()
    check:
      covers.mapIt(it.slotPool.nonCoverClaimed).foldl(a + b) == 0
      spam[1 .. 3].mapIt(it.reclaimCount).foldl(a + b) == 1

  asyncTest "forward stopped in retry after failed write keeps slot and proof":
    let (nodes, spam, _) = setupNodes(5)
    startAndDeferStop(nodes)
    let covers = nodes[1 .. 3].mapIt(it.attachCover())
    var dialers: seq[HoldingDialer]
    for hop in nodes[1 .. 3]:
      let dialer = await hop.holdHopStreams(nodes[1 ..^ 1].filterIt(it != hop))
      dialer.holdWrites = true
      dialers.add(dialer)

    check (await nodes.sendToLast()).isOk
    checkUntilTimeout:
      dialers.anyIt(it.firstHeld())
    let held = dialers.filterIt(it.firstHeld())[0].streams[0]

    # The write fails, and the retry waits for the reset of the failed stream.
    held.closing = Future[void].Raising([CancelledError]).init("HoldingStream.closing")
    held.failWrites(newLPStreamResetError())
    checkUntilTimeout:
      held.isClosed

    # The stop cancels the forward in that wait, and then it waits for the reset.
    let stops = nodes[1 .. 3].mapIt(it.stop())
    checkUntilTimeout:
      nodes[1 .. 3].allIt(it.ongoingMixMessages.len == 0)
    held.closing.complete()
    for stopping in stops:
      check await stopping.join().withTimeout(2.seconds)
    check:
      covers.mapIt(it.slotPool.nonCoverClaimed).foldl(a + b) == 1
      spam[1 .. 3].mapIt(it.reclaimCount).foldl(a + b) == 0

  asyncTest "forward with failed write keeps slot and proof":
    let (nodes, spam, _) = setupNodes(5)
    startAndDeferStop(nodes)
    for hop in nodes[1 .. 3]:
      hop.failWrites()
    let covers = nodes[1 .. 3].mapIt(it.attachCover())
    let errorsBefore = errorCount("Intermediate", "DIAL_FAILED")

    check (await nodes.sendToLast()).isOk
    # The forward path counts a failed write as DIAL_FAILED.
    checkUntilTimeout:
      errorCount("Intermediate", "DIAL_FAILED") == errorsBefore + 1
    check:
      covers.mapIt(it.slotPool.nonCoverClaimed).foldl(a + b) == 1
      spam[1 .. 3].mapIt(it.reclaimCount).foldl(a + b) == 0

  asyncTest "successful forward keeps slot and proof":
    let (nodes, spam, _) = setupNodes(5)
    startAndDeferStop(nodes)
    let covers = nodes[1 .. 3].mapIt(it.attachCover())

    check (await nodes.sendToLast()).isOk
    # The first two hops forward the packet, and the third hop is the exit.
    checkUntilTimeout:
      covers.mapIt(it.slotPool.nonCoverClaimed).foldl(a + b) == 2
    check spam[1 .. 3].mapIt(it.reclaimCount).foldl(a + b) == 0

suite "Slot refund - message API lifecycle":
  asyncTeardown:
    checkTrackers()

  for stopProtocol in [false, true]:
    asyncTest "service send ends and refunds unwritten proof, stop=" & $stopProtocol:
      let (nodes, spam, delays) = setupNodes(5)
      startAndDeferStop(nodes)
      let ct = nodes[0].attachCover()
      delays[0].delay = LongWait
      let sending =
        nodes[0].send(MixDestination.exitNode(nodes[^1].peerId), TestCodec, @[1.byte])
      checkUntilTimeout:
        spam[0].generated == 1
      check ct.slotPool.nonCoverClaimed == 1
      if stopProtocol:
        await nodes[0].stop()
        check (await sending.wait(2.seconds)).error == "send: mix protocol has stopped"
      else:
        await sending.cancelAndWait()
        check sending.cancelled
      check:
        ct.slotPool.nonCoverClaimed == 0
        spam[0].reclaimed == @[@[1.byte]]
        nodes[0].surbCredsLen == 0
        nodes[0].ongoingLocalSends.len == 0

  for stopProtocol in [false, true]:
    asyncTest "caller-owned SURB send ends and refunds unwritten proof, stop=" &
      $stopProtocol:
      let (nodes, spam, delays) = setupNodes(5)
      startAndDeferStop(nodes)
      let ct = nodes[0].attachCover()
      delays[0].delay = LongWait
      var created = nodes[^1]
        .createSurb(MixDestination.exitNode(nodes[0].peerId))
        .expectMove("SURB")
      let sending = nodes[0].sendWithSurb(move(created.surb), @[1.byte])
      checkUntilTimeout:
        spam[0].generated == 1
      check ct.slotPool.nonCoverClaimed == 1
      if stopProtocol:
        await nodes[0].stop()
        check (await sending.wait(2.seconds)).isErr
      else:
        await sending.cancelAndWait()
        check sending.cancelled
      check:
        ct.slotPool.nonCoverClaimed == 0
        spam[0].reclaimed == @[@[1.byte]]
        nodes[0].ongoingLocalSends.len == 0
