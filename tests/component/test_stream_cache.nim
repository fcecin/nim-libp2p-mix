# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/sequtils
import chronos, results
import libp2p/[switch, peerid, multiaddress, varint, dialer, protocols/protocol]
import libp2p_mix
import
  libp2p_mix/[mix_protocol, mix_node, cover_traffic, delay_strategy, spam_protection]
import ../tools/[lifecycle, unittest, crypto]
import ../[utils, spam_protection_impl]

const
  ReplyParams = MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(1'u8))
  BigPacketLen = 16 * 1024 * 1024
    ## More than the send window of each muxer and the socket buffers of
    ## loopback, so a write of this size waits for the next hop to read.

proc exchange(
    sender: MixProtocol, destination: MixDestination, codec: string, value: byte
) {.async.} =
  let conn = sender.toConnection(destination, codec, ReplyParams).expect("connection")
  defer:
    await conn.close()
  await conn.writeLp(@[value]).wait(5.seconds)
  let reply = await conn.readLp(1024).wait(5.seconds)
  check reply == @[value]

proc lengthPrefixed(data: seq[byte]): seq[byte] =
  ## `data` after its varint length, as `writeLp` writes it.
  @(PB.toBytes(data.len.uint64).toOpenArray()) & data

type StallingHop = ref object of LPProtocol
  ## A next hop that reads a part of its first mix stream, fires `prefixRead`,
  ## and then reads nothing until `hold` fires. `firstStream` keeps the bytes of
  ## the first stream, and `firstEnded` fires when that stream ends. `streams`
  ## keeps the frames of each later stream.
  prefixRead: AsyncEvent
  hold: AsyncEvent
  firstEnded: AsyncEvent
  accepted: int
  firstStream: seq[byte]
  streams: seq[seq[seq[byte]]]

proc new(T: typedesc[StallingHop]): StallingHop =
  let hop = StallingHop(
    prefixRead: newAsyncEvent(), hold: newAsyncEvent(), firstEnded: newAsyncEvent()
  )

  proc handler(conn: Connection, proto: string) {.async: (raises: [CancelledError]).} =
    let first = hop.accepted == 0
    inc hop.accepted
    try:
      if first:
        var buf = newSeq[byte](64 * 1024)
        let n = await conn.readOnce(addr buf[0], buf.len)
        hop.firstStream.add(buf[0 ..< n])
        hop.prefixRead.fire()
        await hop.hold.wait()
        while true:
          let more = await conn.readOnce(addr buf[0], buf.len)
          if more == 0:
            break
          hop.firstStream.add(buf[0 ..< more])
      else:
        hop.streams.add(@[])
        let index = hop.streams.high
        while true:
          hop.streams[index].add(await conn.readLp(2 * BigPacketLen))
    except LPStreamError:
      # The stream ended, or the sender reset it in a frame.
      discard
    finally:
      await conn.close()
      if first:
        hop.firstEnded.fire()

  hop.handler = handler
  hop.codec = MixProtocolID
  hop

proc startStallingHop(
    transport: TestTransport
): Future[tuple[switch: Switch, hop: StallingHop]] {.async.} =
  ## A started switch over `transport`, with a `StallingHop` for the mix
  ## protocol.
  let address =
    if transport == TestTransport.Quic:
      "/ip4/127.0.0.1/udp/0/quic-v1"
    else:
      "/ip4/127.0.0.1/tcp/0"
  let switch = createSwitch(MultiAddress.init(address).tryGet(), transport = transport)
  let hop = StallingHop.new()
  switch.mount(hop)
  await switch.start()
  (switch, hop)

type
  HeldProof = ref object of SpamProtection
    ## Makes each proof only after `release` fires, and makes cover proofs at
    ## the send. So a direct cover send waits in its proof.
    started: AsyncEvent
    release: AsyncEvent

  HeldStopCover = ref object of CoverTraffic
    ## A cover traffic whose stop waits until `release` fires.
    release: AsyncEvent

  CountingStream = ref object of Connection
    ## A hop stream with no connection. It counts its writes, and `onWrite` runs
    ## in each write. A read fails at once, so the hop reader of the protocol
    ## ends.
    writes: int
    onWrite: proc() {.gcsafe, raises: [].}

  PendingDialer = ref object of Dialer
    ## Each dial waits until `ready` fires, and then gives `stream`.
    ready: AsyncEvent
    stream: CountingStream

method generateProof(
    self: HeldProof, bindingData: seq[byte]
): Result[ProofResult, string] {.gcsafe, raises: [].} =
  ok(ProofResult(proof: newSeq[byte](self.proofSize)))

method generateProofAsync(
    self: HeldProof, bindingData: seq[byte]
): Future[Result[ProofResult, string]] {.async: (raises: [CancelledError]).} =
  self.started.fire()
  await self.release.wait()
  return self.generateProof(bindingData)

method precomputeCoverProofs(self: HeldProof): bool {.gcsafe, raises: [].} =
  false

method start(ct: HeldStopCover) {.async: (raises: [CancelledError]).} =
  discard

method stop(ct: HeldStopCover) {.async: (raises: []).} =
  await noCancel ct.release.wait()

method write(
    self: CountingStream, msg: sink seq[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError]).} =
  inc self.writes
  if not self.onWrite.isNil:
    self.onWrite()

method readOnce(
    self: CountingStream, pbytes: pointer, nbytes: int
): Future[int] {.async: (raises: [CancelledError, LPStreamError]).} =
  raise newLPStreamEOFError()

method dial(
    self: PendingDialer,
    peerId: PeerId,
    addrs: seq[MultiAddress],
    protos: seq[string],
    forceDial = false,
): Future[Stream] {.async: (raises: [DialFailedError, CancelledError]).} =
  await self.ready.wait()
  return self.stream

proc holdDials(node: MixProtocol, peerId: PeerId): PendingDialer =
  ## Makes each dial of `node` wait until the `ready` of the result fires.
  let stream = CountingStream(peerId: peerId, dir: Direction.Out)
  stream.initStream()
  let switch = node.switch
  result = PendingDialer(
    PendingDialer.new(
      switch.peerInfo.peerId, switch.connManager, switch.peerStore, switch.transports,
      switch.ms,
    )
  )
  result.ready = newAsyncEvent()
  result.stream = stream
  switch.dialer = result

proc holdStop(node: MixProtocol): HeldStopCover =
  ## Gives `node` a cover traffic whose stop waits until the `release` of the
  ## result fires.
  result = HeldStopCover(release: newAsyncEvent())
  node.coverTraffic = Opt.some(CoverTraffic(result))

suite "Hop stream cache":
  asyncTeardown:
    checkTrackers()

  asyncTest "concurrent requests and retries reuse one cached stream per peer":
    let echoProto = EchoProtocol.new()
    let nodes = await setupMixNodes(
      5, destReadBehavior = Opt.some((codec: echoProto.codec, callback: readLp(1024)))
    )
    nodes[^1].switch.mount(echoProto)
    startAndDeferStop(nodes)
    let sender = nodes[0]
    let destination = nodes[^1].toMixDestination()
    for round in 0 .. 1:
      var pending: seq[Future[void]]
      for i in 0 ..< 8:
        pending.add(exchange(sender, destination, echoProto.codec, i.byte))
      await allFutures(pending)
      for request in pending:
        await request
      let streams = outgoingMixStreams(sender.switch)
      check streams.len > 0
      # One cached stream for each peer. A second stream to the same peer is
      # the duplicate that this test exists to catch.
      check streams.mapIt(it.peerId).deduplicate().len == streams.len
      if round == 0:
        # Close the cached streams and keep the cache entries, as a peer reset does.
        await allFutures(streams.mapIt(it.close()))

  asyncTest "protocol stop fails a cover send that waits on a dial and refuses a new dial":
    let nodes = await setupMixNodes(1)
    startAndDeferStop(nodes)

    let hold = HoldingServer.new()
    defer:
      await hold.close()

    let hopPeerId = PeerId.random(rng()).expect("peer id")
    let hopAddr = hold.address()
    let errorsBefore = errorCount("Cover", "SEND_FAILED")
    let sending = nodes[0].sendCoverPacket(hopPeerId, hopAddr, @[1.byte])
    checkUntilTimeout:
      hold.connections.len == 1
    check not sending.finished

    # The stop cancels the dial. The send fails, and the counters record no
    # failure of the hop.
    await nodes[0].stop()
    let stopped = await sending.wait(2.seconds)
    check:
      stopped.isErr
      errorCount("Cover", "SEND_FAILED") == errorsBefore
    # A send that the stop refuses counts nothing either.
    let refused = await nodes[0].sendCoverPacket(hopPeerId, hopAddr, @[1.byte])
    check:
      refused.isErr
      errorCount("Cover", "SEND_FAILED") == errorsBefore
      hold.connections.len == 1

  asyncTest "protocol restart dials again":
    let nodes = await setupMixNodes(1)
    startAndDeferStop(nodes)
    let hold = HoldingServer.new()
    defer:
      await hold.close()

    await nodes[0].stop()
    await nodes[0].start()
    let sending = nodes[0].sendCoverPacket(
      PeerId.random(rng()).expect("peer id"), hold.address(), @[1.byte]
    )
    checkUntilTimeout:
      hold.connections.len == 1
    await sending.cancelAndWait()

  asyncTest "protocol stop closes the cached hop streams":
    let echoProto = EchoProtocol.new()
    let nodes = await setupMixNodes(
      5, destReadBehavior = Opt.some((codec: echoProto.codec, callback: readLp(1024)))
    )
    nodes[^1].switch.mount(echoProto)
    startAndDeferStop(nodes)
    let sender = nodes[0]

    await exchange(sender, nodes[^1].toMixDestination(), echoProto.codec, 7)
    check outgoingMixStreams(sender.switch).len > 0
    await sender.stop()
    check outgoingMixStreams(sender.switch).len == 0

  asyncTest "protocol stop fails a send that waits on a dial and refunds its slot and proof":
    # A node that counts the proofs it reclaims, with a slot pool whose epochs
    # change only when the test says so.
    let info = MixNodeInfo.generateRandom(0, rng())
    let spam = newReclaimCountingSpamProtection()
    let node = MixProtocol.new(
      info,
      createSwitch(info.multiAddr, Opt.some(info.libp2pPrivKey)),
      spamProtection = Opt.some(SpamProtection(spam)),
      delayStrategy = Opt.some(DelayStrategy(NoSamplingDelayStrategy.new(rng()))),
    )
    node.switch.mount(node)
    startAndDeferStop(@[node])
    # Attached after the start, so no emission loop runs and only the send under
    # test claims a slot and dials the server. The epoch is set by hand.
    let cover =
      ConstantRateCoverTraffic.new(totalSlots = 4, useInternalEpochTimer = false)
    cover.onEpochChange(1)
    node.coverTraffic = Opt.some(CoverTraffic(cover))

    let hold = HoldingServer.new()
    defer:
      await hold.close()

    # Every pool member has the address of the server, so the first hop of any
    # path keeps the send in its dial.
    for member in MixNodeInfo.generateRandomMany(3, rng()):
      var hop = member.toMixPubInfo()
      hop.multiAddr = hold.address()
      node.nodePool.add(hop)
    let destination = MixNodeInfo.generateRandom(0, rng())
    let errorsBefore = errorCount("Entry", "SEND_FAILED")
    let sending = node.anonymizeLocalProtocolSend(
      newAsyncQueue[seq[byte]](),
      @[1.byte],
      "/test/1.0.0",
      MixDestination.init(destination.peerId, destination.multiAddr),
      0,
    )
    checkUntilTimeout:
      hold.connections.len == 1
    check cover.slotPool.nonCoverClaimed == 1

    # The packet never left this node, so the send gives its slot and proof back.
    await node.stop()
    let stopped = await sending.wait(2.seconds)
    check:
      stopped.isErr
      errorCount("Entry", "SEND_FAILED") == errorsBefore
      cover.slotPool.nonCoverClaimed == 0
      spam.reclaimCount == 1

  for transport in TestTransport:
    asyncTest "send cancelled in write leaves no cut frame for the next send over " &
      $transport:
      let nodes = await setupMixNodes(1, transport = transport)
      startAndDeferStop(nodes)
      let sender = nodes[0]
      let (hopSwitch, hop) = await startStallingHop(transport)
      defer:
        hop.hold.fire()
        await hopSwitch.stop()
      let hopId = hopSwitch.peerInfo.peerId
      let hopAddr = hopSwitch.peerInfo.addrs[0]
      # No byte of the small frames is in the big packet, so a small frame on the
      # first stream after a cut cannot look like a part of the big packet.
      let big = repeat(0xAA'u8, BigPacketLen)

      # The hop reads a part of the first frame and then reads nothing. So the
      # rest of the big packet and the second send wait in the muxer.
      let first = sender.sendCoverPacket(hopId, hopAddr, big)
      check await hop.prefixRead.wait().withTimeout(10.seconds)
      let second = sender.sendCoverPacket(hopId, hopAddr, @[2.byte])
      first.cancelSoon()
      check await first.join().withTimeout(5.seconds)
      check first.cancelled

      # The second send can fail, or go with the stream of the first. A send
      # after the cancel arrives whole.
      hop.hold.fire()
      check await second.join().withTimeout(30.seconds)
      let markerSent =
        await sender.sendCoverPacket(hopId, hopAddr, @[3.byte]).wait(30.seconds)
      let marker = lengthPrefixed(@[3.byte])
      checkUntilTimeout:
        hop.streams.anyIt(@[3.byte] in it) or (
          hop.firstStream.len >= marker.len and
          hop.firstStream[^marker.len .. ^1] == marker
        )
      # The first stream carries the frames in the order of the sends, and
      # it can end in the middle of one. No frame goes on after a cut frame.
      # A reset that sends no RST leaves the stream open, so the wait has a limit.
      discard await hop.firstEnded.wait().withTimeout(10.seconds)
      let written = lengthPrefixed(big) & lengthPrefixed(@[2.byte]) & marker
      check:
        markerSent.isOk
        hop.firstStream.len <= written.len
        hop.firstStream == written[0 ..< hop.firstStream.len]
        concat(hop.streams).allIt(it in @[@[2.byte], @[3.byte]])

  asyncTest "cover send held across a stop and a start does not dial in the new run":
    let proofs =
      HeldProof(proofSize: 4, started: newAsyncEvent(), release: newAsyncEvent())
    let info = MixNodeInfo.generateRandom(0, rng())
    let node = MixProtocol.new(
      info,
      createSwitch(info.multiAddr, Opt.some(info.libp2pPrivKey)),
      spamProtection = Opt.some(SpamProtection(proofs)),
    )
    startAndDeferStop(@[node])
    let hold = HoldingServer.new()
    defer:
      await hold.close()
    let errorsBefore = errorCount("Cover", "SEND_FAILED")

    # A stop does not cancel a direct cover send. So the send waits in its proof
    # through the stop and the start.
    let sending = node.sendCoverPacket(
      PeerId.random(rng()).expect("peer id"), hold.address(), @[1.byte]
    )
    check await proofs.started.wait().withTimeout(5.seconds)
    await node.stop()
    await node.start()
    proofs.release.fire()

    let sent = await sending.wait(5.seconds)
    check:
      sent.isErr
      hold.connections.len == 0
      errorCount("Cover", "SEND_FAILED") == errorsBefore

  asyncTest "cover send that starts while the stop waits for the cover traffic does not dial":
    let nodes = await setupMixNodes(1)
    startAndDeferStop(nodes)
    let node = nodes[0]
    let cover = node.holdStop()
    defer:
      cover.release.fire()
    let hold = HoldingServer.new()
    defer:
      await hold.close()

    let stopping = node.stop()
    let sent = await node
      .sendCoverPacket(
        PeerId.random(rng()).expect("peer id"), hold.address(), @[1.byte]
      )
      .wait(5.seconds)
    cover.release.fire()
    await stopping
    check:
      sent.isErr
      sent.error == "sendCoverPacket: mix protocol is not running"
      hold.connections.len == 0

  asyncTest "send that resumes after the stop began does not write":
    let nodes = await setupMixNodes(1)
    startAndDeferStop(nodes)
    let node = nodes[0]
    let hopId = PeerId.random(rng()).expect("peer id")
    let hopAddr = MultiAddress.init("/ip4/127.0.0.1/tcp/1").tryGet()
    let dialer = node.holdDials(hopId)

    # Both sends wait for the one dial. The first write starts the stop, before
    # the second send resumes.
    var stopping: Future[void].Raising([])
    dialer.stream.onWrite = proc() {.gcsafe, raises: [].} =
      if dialer.stream.writes == 1:
        stopping = node.stop()
    let first = node.sendCoverPacket(hopId, hopAddr, @[1.byte])
    let second = node.sendCoverPacket(hopId, hopAddr, @[2.byte])
    dialer.ready.fire()
    let sent = await first.wait(5.seconds)
    let refused = await second.wait(5.seconds)
    check not stopping.isNil
    if not stopping.isNil:
      await stopping.wait(5.seconds)
    check:
      sent.isOk
      refused.isErr
      dialer.stream.writes == 1

  asyncTest "dial that ends while the stop waits for the cover traffic is closed":
    let nodes = await setupMixNodes(1)
    startAndDeferStop(nodes)
    let node = nodes[0]
    let cover = node.holdStop()
    defer:
      cover.release.fire()
    let hopId = PeerId.random(rng()).expect("peer id")
    let hopAddr = MultiAddress.init("/ip4/127.0.0.1/tcp/1").tryGet()
    let dialer = node.holdDials(hopId)

    let sending = node.sendCoverPacket(hopId, hopAddr, @[1.byte])
    let stopping = node.stop()
    dialer.ready.fire()
    let sent = await sending.wait(5.seconds)
    cover.release.fire()
    await stopping.wait(5.seconds)
    check:
      sent.isErr
      dialer.stream.writes == 0
      dialer.stream.isClosed
