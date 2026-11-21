# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/[importutils, sequtils, sets, strutils, tables]
import chronos, results
import libp2p/[switch, peerid, multiaddress, varint, protocols/protocol]
import libp2p_mix
import
  libp2p_mix/[mix_protocol, mix_node, cover_traffic, delay_strategy, spam_protection]
import ../tools/[lifecycle, unittest, crypto]
import ../[utils, spam_protection_impl]

when defined(enable_mix_benchmarks):
  import libp2p_mix/benchmark

privateAccess(MixProtocol)

const
  ReplyParams = MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(1'u8))
  TestCodec = "/mix/test/stream-cache/1.0.0"
  EntryPayload = newSeq[byte](16)
    ## Benchmark mode reads the first 16 bytes of a message as its metadata.
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

proc peerId(node: MixProtocol): PeerId =
  node.switch.peerInfo.peerId

proc address(node: MixProtocol): MultiAddress =
  node.switch.peerInfo.addrs[0]

const StreamName: array[TestTransport, string] =
  ["LPChannel", "YamuxStream", "QuicStream"]
  ## The `objName` of a hop stream on each transport.

proc lengthPrefixed(data: seq[byte]): seq[byte] =
  ## `data` after its varint length, as `writeLp` writes it.
  @(PB.toBytes(data.len.uint64).toOpenArray()) & data

proc coverFrames(packet: seq[byte]): seq[seq[byte]] =
  ## The frames of a cover send of `packet` with no spam protection. In
  ## benchmark mode a zero metadata frame comes before the packet.
  when defined(enable_mix_benchmarks):
    @[Metadata().serialize(), packet]
  else:
    @[packet]

proc coverWrite(packet: seq[byte]): seq[byte] =
  ## The bytes of the one write of a cover send of `packet`.
  concat(coverFrames(packet).mapIt(lengthPrefixed(it)))

type StallingHop = ref object of LPProtocol
  ## A next hop that reads the length and the first byte of the first frame on
  ## its first mix stream, fires `prefixRead`, and then reads nothing until
  ## `release`. After that it reads each frame whole. `streams` keeps the
  ## frames of each stream that it accepted, and `failures` keeps each read
  ## error that is not the end of a stream.
  prefixRead: AsyncEvent
  hold: AsyncEvent
  streams: seq[seq[seq[byte]]]
  connections: seq[Connection]
  failures: seq[string]

proc new(T: typedesc[StallingHop]): StallingHop =
  let hop = StallingHop(prefixRead: newAsyncEvent(), hold: newAsyncEvent())

  proc handler(conn: Connection, proto: string) {.async: (raises: [CancelledError]).} =
    let index = hop.streams.len
    hop.streams.add(@[])
    hop.connections.add(conn.getWrapped())
    try:
      if index == 0:
        let length = await conn.readVarint()
        var frame = newSeq[byte](length.int)
        await conn.readExactly(addr frame[0], 1)
        hop.prefixRead.fire()
        await hop.hold.wait()
        await conn.readExactly(addr frame[1], frame.len - 1)
        hop.streams[index].add(frame)
      while true:
        hop.streams[index].add(await conn.readLp(2 * BigPacketLen))
    except LPStreamEOFError:
      return
    except LPStreamError as e:
      hop.failures.add(e.msg)
    finally:
      await conn.close()

  hop.handler = handler
  hop.codec = MixProtocolID
  hop

proc release(hop: StallingHop) =
  hop.hold.fire()

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

  asyncTest "send cancelled in write finishes its packet on the same stream":
    let nodes = await setupMixNodes(5)
    startAndDeferStop(nodes)
    let sender = nodes[0]
    let dialer = await sender.holdHopStreams(nodes[1 ..^ 1])
    dialer.holdWrites = true

    let sending = sender.anonymizeLocalProtocolSend(
      newAsyncQueue[seq[byte]](),
      EntryPayload,
      TestCodec,
      nodes[^1].toMixDestination(),
      0,
    )
    checkUntilTimeout:
      dialer.firstHeld()
    let held = dialer.streams[0]

    # The cancel ends the wait of the sender while the write still waits.
    sending.cancelSoon()
    check await sending.join().withTimeout(1.seconds)
    check:
      sending.cancelled
      held.pendingWrites.len == 1
      sender.connPool.getOrDefault(held.peerId) == Connection(held)

    held.release()
    checkUntilTimeout:
      held.written.len == 1
    check:
      held.cancelledWrites == 0
      not held.isClosed
      sender.connPool.getOrDefault(held.peerId) == Connection(held)
      sender.hopWrites.len == 0
      dialer.streams.len == 1

  asyncTest "send behind cancelled write goes out after it on the same stream":
    let nodes = await setupMixNodes(2)
    startAndDeferStop(nodes)
    let sender = nodes[0]
    let hop = nodes[1]
    let dialer = await sender.holdHopStreams(@[hop])
    dialer.holdWrites = true

    let first = sender.sendCoverPacket(hop.peerId, hop.address, @[1.byte])
    checkUntilTimeout:
      dialer.firstHeld()
    let held = dialer.streams[0]
    first.cancelSoon()
    check await first.join().withTimeout(1.seconds)

    let second = sender.sendCoverPacket(hop.peerId, hop.address, @[2.byte])
    checkUntilTimeout:
      sender.waitingWrites(held) == 1
    check:
      first.cancelled
      not second.finished
      held.pendingWrites.len == 1

    held.hold = false
    held.release()
    let sent = await second.wait(2.seconds)
    check:
      sent.isOk
      held.written == @[coverWrite(@[1.byte]), coverWrite(@[2.byte])]
      dialer.streams.len == 1
      held.cancelledWrites == 0

  asyncTest "send cancelled while it waits for a write writes nothing":
    let nodes = await setupMixNodes(2)
    startAndDeferStop(nodes)
    let sender = nodes[0]
    let hop = nodes[1]
    let dialer = await sender.holdHopStreams(@[hop])
    dialer.holdWrites = true

    let first = sender.sendCoverPacket(hop.peerId, hop.address, @[1.byte])
    checkUntilTimeout:
      dialer.firstHeld()
    let held = dialer.streams[0]
    let second = sender.sendCoverPacket(hop.peerId, hop.address, @[2.byte])
    checkUntilTimeout:
      sender.waitingWrites(held) == 1
    check held.pendingWrites.len == 1
    second.cancelSoon()
    check await second.join().withTimeout(1.seconds)
    check:
      second.cancelled
      sender.waitingWrites(held) == 0

    held.release()
    let sent = await first.wait(2.seconds)
    check:
      sent.isOk
      held.written == @[coverWrite(@[1.byte])]
      held.cancelledWrites == 0
      dialer.streams.len == 1

  asyncTest "sends behind a held write go out in the order they came":
    let nodes = await setupMixNodes(2)
    startAndDeferStop(nodes)
    let sender = nodes[0]
    let hop = nodes[1]
    let dialer = await sender.holdHopStreams(@[hop])
    dialer.holdWrites = true

    let first = sender.sendCoverPacket(hop.peerId, hop.address, @[1.byte])
    checkUntilTimeout:
      dialer.firstHeld()
    let held = dialer.streams[0]
    let values = toSeq(2'u8 .. 6'u8)
    let sends =
      @[first] & values.mapIt(sender.sendCoverPacket(hop.peerId, hop.address, @[it]))
    checkUntilTimeout:
      sender.waitingWrites(held) == values.len
    check held.pendingWrites.len == 1

    held.hold = false
    held.release()
    await allFutures(sends).wait(2.seconds)
    check:
      sends.allIt(it.read().isOk)
      held.written == (@[1'u8] & values).mapIt(coverWrite(@[it]))
      dialer.streams.len == 1

  asyncTest "send beyond the waiting limit fails the sends behind a stalled stream":
    let nodes = await setupMixNodes(2)
    startAndDeferStop(nodes)
    let sender = nodes[0]
    let hop = nodes[1]
    let dialer = await sender.holdHopStreams(@[hop])
    dialer.holdWrites = true

    let first = sender.sendCoverPacket(hop.peerId, hop.address, @[1.byte])
    checkUntilTimeout:
      dialer.firstHeld()
    let held = dialer.streams[0]
    let packet = newSeq[byte](4096)
    let fit = WaitingBytesLimit div coverWrite(packet).len
    let waiting =
      toSeq(1 .. fit).mapIt(sender.sendCoverPacket(hop.peerId, hop.address, packet))
    check sender.waitingWrites(held) == fit

    # One more send would go past the limit, and the writes made no progress
    # for a long time, so the stream counts as stalled. The protocol closes the
    # connection to the hop, ends the write and fails each send that waits.
    sender.ageHopGate(held)
    let beyond =
      await sender.sendCoverPacket(hop.peerId, hop.address, packet).wait(2.seconds)
    await allFutures(waiting).wait(5.seconds)
    check:
      beyond.isErr
      beyond.error.contains("stalled")
      waiting.allIt(it.read().isErr)
      held.cancelledWrites == 1
      held.written.len == 0
      held.connection.closes == 1
      sender.backedOffUntil.hasKey(hop.peerId)

    # The first send writes one more time, to a new stream.
    checkUntilTimeout:
      dialer.streams.len == 2 and dialer.streams[1].pendingWrites.len == 1
    dialer.streams[1].release()
    let sent = await first.wait(2.seconds)
    check:
      sent.isOk
      dialer.streams[1].written == @[coverWrite(@[1.byte])]
      held.isClosed

  asyncTest "send beyond the waiting limit of a busy stream fails alone":
    let nodes = await setupMixNodes(2)
    startAndDeferStop(nodes)
    let sender = nodes[0]
    let hop = nodes[1]
    let dialer = await sender.holdHopStreams(@[hop])
    dialer.holdWrites = true

    let first = sender.sendCoverPacket(hop.peerId, hop.address, @[1.byte])
    checkUntilTimeout:
      dialer.firstHeld()
    let held = dialer.streams[0]
    let packet = newSeq[byte](4096)
    let fit = WaitingBytesLimit div coverWrite(packet).len
    let waiting =
      toSeq(1 .. fit).mapIt(sender.sendCoverPacket(hop.peerId, hop.address, packet))
    check sender.waitingWrites(held) == fit

    # The write in progress started a moment ago, so the stream is busy. Only
    # the send that would go past the limit fails.
    let beyond =
      await sender.sendCoverPacket(hop.peerId, hop.address, packet).wait(2.seconds)
    check:
      beyond.isErr
      beyond.error.contains("too many writes")
      sender.waitingWrites(held) == fit
      held.cancelledWrites == 0
      sender.switch.isConnected(hop.peerId)
      sender.backedOffUntil.len == 0

    held.hold = false
    held.release()
    await allFutures(@[first] & waiting).wait(5.seconds)
    check:
      first.read().isOk
      waiting.allIt(it.read().isOk)
      held.written.len == 1 + fit
      dialer.streams.len == 1

  asyncTest "frame bigger than the waiting limit fails alone behind an old write":
    let nodes = await setupMixNodes(2)
    startAndDeferStop(nodes)
    let sender = nodes[0]
    let hop = nodes[1]
    let dialer = await sender.holdHopStreams(@[hop])
    dialer.holdWrites = true

    let first = sender.sendCoverPacket(hop.peerId, hop.address, @[1.byte])
    checkUntilTimeout:
      dialer.firstHeld()
    let held = dialer.streams[0]

    # No write waits, so a frame that alone goes past the limit is not a stall,
    # also behind a write that made no progress for a long time.
    sender.ageHopGate(held)
    let big = newSeq[byte](WaitingBytesLimit + 1)
    let sent =
      await sender.sendCoverPacket(hop.peerId, hop.address, big).wait(2.seconds)
    check:
      sent.isErr
      sent.error.contains("too many writes")
      held.cancelledWrites == 0
      held.connection.closes == 0
      sender.backedOffUntil.len == 0

    held.release()
    check (await first.wait(2.seconds)).isOk

  asyncTest "send to a next hop that closes each new stream fails before its write":
    let nodes = await setupMixNodes(2)
    startAndDeferStop(nodes)
    let sender = nodes[0]
    let hop = nodes[1]
    let dialer = await sender.holdHopStreams(@[hop])

    let first =
      await sender.sendCoverPacket(hop.peerId, hop.address, @[1.byte]).wait(2.seconds)
    check dialer.streams.len == 1
    dialer.streams[0].endRead()

    # The send replaces the stream that the next hop closed one time. The next
    # hop closes the new stream too, so the send fails before it writes.
    dialer.endStreams = true
    let sent =
      await sender.sendCoverPacket(hop.peerId, hop.address, @[2.byte]).wait(2.seconds)
    check dialer.streams.len == 2
    check:
      first.isOk
      sent.isErr
      sent.error.contains("closed a new stream")
      dialer.streams[1].written.len == 0
      Connection(dialer.streams[1]) in sender.unusableStreams

  asyncTest "write failed with live sender is retried on a new stream":
    let nodes = await setupMixNodes(2)
    startAndDeferStop(nodes)
    let sender = nodes[0]
    let hop = nodes[1]
    let dialer = await sender.holdHopStreams(@[hop])
    dialer.holdWrites = true

    let first = sender.sendCoverPacket(hop.peerId, hop.address, @[1.byte])
    checkUntilTimeout:
      dialer.firstHeld()
    let held = dialer.streams[0]

    # A reset of a Yamux stream fails its writes with this error.
    dialer.holdWrites = false
    held.failWrites(newLPStreamEOFError())
    let sent = await first.wait(2.seconds)
    check dialer.streams.len == 2
    check:
      sent.isOk
      dialer.streams[1].written == @[coverWrite(@[1.byte])]
      held.isClosed
      sender.connPool.getOrDefault(hop.peerId) == Connection(dialer.streams[1])

  asyncTest "retried write that fails is not retried again":
    let nodes = await setupMixNodes(2)
    startAndDeferStop(nodes)
    let sender = nodes[0]
    let hop = nodes[1]
    let dialer = await sender.holdHopStreams(@[hop])
    dialer.holdWrites = true

    let first = sender.sendCoverPacket(hop.peerId, hop.address, @[1.byte])
    checkUntilTimeout:
      dialer.firstHeld()
    dialer.streams[0].failWrites(newLPStreamResetError())
    checkUntilTimeout:
      dialer.streams.len == 2 and dialer.streams[1].pendingWrites.len == 1

    dialer.streams[1].failWrites(newLPStreamResetError())
    let sent = await first.wait(2.seconds)
    check:
      sent.isErr
      dialer.streams.len == 2
      dialer.streams.allIt(it.written.len == 0)

  asyncTest "retry stopped in write counts no send failure":
    let nodes = await setupMixNodes(2)
    startAndDeferStop(nodes)
    let sender = nodes[0]
    let hop = nodes[1]
    let dialer = await sender.holdHopStreams(@[hop])
    dialer.holdWrites = true

    let first = sender.sendCoverPacket(hop.peerId, hop.address, @[1.byte])
    checkUntilTimeout:
      dialer.firstHeld()
    dialer.streams[0].failWrites(newLPStreamEOFError())
    checkUntilTimeout:
      dialer.streams.len == 2 and dialer.streams[1].pendingWrites.len == 1

    let errorsBefore = errorCount("Cover", "SEND_FAILED")
    let stopping = sender.stop()
    check await stopping.join().withTimeout(2.seconds)
    let sent = await first.wait(2.seconds)
    check:
      sent.isErr
      dialer.streams[1].cancelledWrites == 1
      errorCount("Cover", "SEND_FAILED") == errorsBefore

  asyncTest "sends behind a failed write go out on a new stream":
    let nodes = await setupMixNodes(2)
    startAndDeferStop(nodes)
    let sender = nodes[0]
    let hop = nodes[1]
    let dialer = await sender.holdHopStreams(@[hop])
    dialer.holdWrites = true

    let first = sender.sendCoverPacket(hop.peerId, hop.address, @[1.byte])
    checkUntilTimeout:
      dialer.firstHeld()
    let held = dialer.streams[0]
    first.cancelSoon()
    check await first.join().withTimeout(1.seconds)
    let others =
      toSeq(2'u8 .. 3'u8).mapIt(sender.sendCoverPacket(hop.peerId, hop.address, @[it]))
    checkUntilTimeout:
      sender.waitingWrites(held) == others.len

    # The write fails, and its stream can hold a part of the packet. Only that
    # write fails, and the stream lets each other write complete.
    dialer.holdWrites = false
    held.pendingWrites[0].fail(newLPStreamResetError())
    held.hold = false
    held.release()
    await allFutures(others).wait(2.seconds)
    check dialer.streams.len == 2
    let fresh = dialer.streams[1]
    check:
      others.allIt(it.read().isOk)
      held.written.len == 0
      held.isClosed
      fresh.written.len == 2
      coverWrite(@[2.byte]) in fresh.written
      coverWrite(@[3.byte]) in fresh.written

  asyncTest "write that completes after next hop closed its stream is retried":
    let nodes = await setupMixNodes(2)
    startAndDeferStop(nodes)
    let sender = nodes[0]
    let hop = nodes[1]
    let dialer = await sender.holdHopStreams(@[hop])
    dialer.holdWrites = true

    let first = sender.sendCoverPacket(hop.peerId, hop.address, @[1.byte])
    checkUntilTimeout:
      dialer.firstHeld()
    let held = dialer.streams[0]

    # Yamux completes a write in progress when the next hop closes the stream,
    # also when it sent only a part of the write.
    dialer.holdWrites = false
    held.endRead()
    held.release()
    let sent = await first.wait(2.seconds)
    check dialer.streams.len == 2
    check:
      sent.isOk
      dialer.streams[1].written == @[coverWrite(@[1.byte])]
      held.isClosed

  asyncTest "send after next hop closed its idle stream goes out on a new stream":
    let nodes = await setupMixNodes(2)
    startAndDeferStop(nodes)
    let sender = nodes[0]
    let hop = nodes[1]
    let dialer = await sender.holdHopStreams(@[hop])

    let first =
      await sender.sendCoverPacket(hop.peerId, hop.address, @[1.byte]).wait(2.seconds)
    check dialer.streams.len == 1
    let closed = dialer.streams[0]
    closed.endRead()

    let sent =
      await sender.sendCoverPacket(hop.peerId, hop.address, @[2.byte]).wait(2.seconds)
    check dialer.streams.len == 2
    check:
      first.isOk
      sent.isOk
      closed.written == @[coverWrite(@[1.byte])]
      closed.isClosed
      dialer.streams[1].written == @[coverWrite(@[2.byte])]
      sender.connPool.getOrDefault(hop.peerId) == Connection(dialer.streams[1])

  asyncTest "send after next hop closed its stream ends the held write and dials":
    let nodes = await setupMixNodes(2)
    startAndDeferStop(nodes)
    let sender = nodes[0]
    let hop = nodes[1]
    let dialer = await sender.holdHopStreams(@[hop])
    dialer.holdWrites = true

    let first = sender.sendCoverPacket(hop.peerId, hop.address, @[1.byte])
    checkUntilTimeout:
      dialer.firstHeld()
    let held = dialer.streams[0]

    # Mplex and QUIC keep a write in progress after the next hop closed the
    # stream.
    held.endRead()
    dialer.holdWrites = false
    let sent =
      await sender.sendCoverPacket(hop.peerId, hop.address, @[2.byte]).wait(2.seconds)
    let retried = await first.wait(2.seconds)
    check dialer.streams.len == 2
    let fresh = dialer.streams[1]
    check:
      sent.isOk
      retried.isOk
      held.cancelledWrites == 1
      held.written.len == 0
      held.isClosed
      fresh.written.len == 2
      coverWrite(@[1.byte]) in fresh.written
      coverWrite(@[2.byte]) in fresh.written

  asyncTest "send cancelled while it waits for a stream close writes nothing":
    let nodes = await setupMixNodes(2)
    startAndDeferStop(nodes)
    let sender = nodes[0]
    let hop = nodes[1]
    let dialer = await sender.holdHopStreams(@[hop])
    dialer.holdWrites = true

    let first = sender.sendCoverPacket(hop.peerId, hop.address, @[1.byte])
    checkUntilTimeout:
      dialer.firstHeld()
    let held = dialer.streams[0]
    first.cancelSoon()
    check await first.join().withTimeout(1.seconds)
    held.closing = Future[void].Raising([CancelledError]).init("HoldingStream.closing")
    held.failWrites(newLPStreamResetError())
    checkUntilTimeout:
      Connection(held) in sender.unusableStreams

    # The next send waits for the close of the stream that failed.
    dialer.holdWrites = false
    let second = sender.sendCoverPacket(hop.peerId, hop.address, @[2.byte])
    check not second.finished
    second.cancelSoon()
    check await second.join().withTimeout(1.seconds)
    check second.cancelled

    held.closing.complete()
    checkUntilTimeout:
      held.closeEvent.isSet()
    check:
      dialer.streams.len == 1
      held.written.len == 0

  asyncTest "write failed after its sender cancelled is not retried":
    let nodes = await setupMixNodes(2)
    startAndDeferStop(nodes)
    let sender = nodes[0]
    let hop = nodes[1]
    let dialer = await sender.holdHopStreams(@[hop])
    dialer.holdWrites = true

    let first = sender.sendCoverPacket(hop.peerId, hop.address, @[1.byte])
    checkUntilTimeout:
      dialer.firstHeld()
    let held = dialer.streams[0]
    first.cancelSoon()
    check await first.join().withTimeout(1.seconds)

    held.failWrites(newLPStreamResetError())
    checkUntilTimeout:
      sender.hopWrites.len == 0
    check:
      dialer.streams.len == 1
      Connection(held) in sender.unusableStreams

    # The next send to the hop closes the stream and dials a new one.
    dialer.holdWrites = false
    let sent =
      await sender.sendCoverPacket(hop.peerId, hop.address, @[2.byte]).wait(2.seconds)
    check dialer.streams.len == 2
    check:
      sent.isOk
      held.wasReset
      dialer.streams[1].written == @[coverWrite(@[2.byte])]

  asyncTest "protocol stop cancels a held write and closes its stream":
    let nodes = await setupMixNodes(2)
    startAndDeferStop(nodes)
    let sender = nodes[0]
    let hop = nodes[1]
    let dialer = await sender.holdHopStreams(@[hop])
    dialer.holdWrites = true

    let first = sender.sendCoverPacket(hop.peerId, hop.address, @[1.byte])
    checkUntilTimeout:
      dialer.firstHeld()
    let held = dialer.streams[0]

    let stopping = sender.stop()
    check await stopping.join().withTimeout(2.seconds)
    let stopped = await first.wait(2.seconds)
    check:
      stopped.isErr
      held.cancelledWrites == 1
      held.wasReset
      sender.hopWrites.len == 0
      sender.connPool.len == 0
      sender.backedOffUntil.len == 0
      dialer.streams.len == 1

    # After a restart, a send dials a new stream.
    await sender.start()
    dialer.holdWrites = false
    let sent =
      await sender.sendCoverPacket(hop.peerId, hop.address, @[2.byte]).wait(2.seconds)
    check dialer.streams.len == 2
    check:
      sent.isOk
      dialer.streams[1].written == @[coverWrite(@[2.byte])]

  asyncTest "send that waits for a stream reset across a stop fails with the stop":
    let nodes = await setupMixNodes(2)
    startAndDeferStop(nodes)
    let sender = nodes[0]
    let hop = nodes[1]
    let dialer = await sender.holdHopStreams(@[hop])
    dialer.holdWrites = true

    # A write that fails after its sender cancelled leaves its stream unusable.
    let first = sender.sendCoverPacket(hop.peerId, hop.address, @[1.byte])
    checkUntilTimeout:
      dialer.firstHeld()
    let held = dialer.streams[0]
    first.cancelSoon()
    check await first.join().withTimeout(1.seconds)
    held.closing = Future[void].Raising([CancelledError]).init("HoldingStream.closing")
    held.failWrites(newLPStreamResetError())
    checkUntilTimeout:
      Connection(held) in sender.unusableStreams

    # The next send waits for the reset of that stream. The stop waits for the
    # reset too, and the send then fails with the stop.
    dialer.holdWrites = false
    let errorsBefore = errorCount("Cover", "SEND_FAILED")
    let second = sender.sendCoverPacket(hop.peerId, hop.address, @[2.byte])
    check not second.finished
    let stopping = sender.stop()
    check not await stopping.join().withTimeout(100.milliseconds)
    held.closing.complete()
    check await stopping.join().withTimeout(2.seconds)
    let sent = await second.wait(2.seconds)
    await sender.start()
    check:
      sent.isErr
      dialer.streams.len == 1
      dialer.streams.allIt(it.written.len == 0)
      sender.connPool.len == 0
      sender.backedOffUntil.len == 0
      errorCount("Cover", "SEND_FAILED") == errorsBefore

  asyncTest "repeated start keeps a send that waits for a write":
    let nodes = await setupMixNodes(2)
    startAndDeferStop(nodes)
    let sender = nodes[0]
    let hop = nodes[1]
    let dialer = await sender.holdHopStreams(@[hop])
    dialer.holdWrites = true

    let first = sender.sendCoverPacket(hop.peerId, hop.address, @[1.byte])
    checkUntilTimeout:
      dialer.firstHeld()
    let held = dialer.streams[0]
    let second = sender.sendCoverPacket(hop.peerId, hop.address, @[2.byte])
    checkUntilTimeout:
      sender.waitingWrites(held) == 1

    # The switch starts the protocol too, so a running protocol can get a start.
    await sender.start()
    held.hold = false
    held.release()
    check:
      (await first.wait(2.seconds)).isOk
      (await second.wait(2.seconds)).isOk
      held.written == @[coverWrite(@[1.byte]), coverWrite(@[2.byte])]

  asyncTest "send over a dial that completes at once writes to the pooled stream":
    # Without the `publishDial` of `getConn`, `startHopWrite` loops with no
    # await, and this test does not end.
    let nodes = await setupMixNodes(2)
    startAndDeferStop(nodes)
    let sender = nodes[0]
    let hop = nodes[1]
    let dialer = await sender.holdHopStreams(@[hop])
    dialer.instant = true

    let sent =
      await sender.sendCoverPacket(hop.peerId, hop.address, @[1.byte]).wait(2.seconds)
    check dialer.streams.len == 1
    check:
      sent.isOk
      dialer.streams[0].written == @[coverWrite(@[1.byte])]
      sender.connPool.getOrDefault(hop.peerId) == Connection(dialer.streams[0])

  asyncTest "connection closed in write releases reply credentials and keeps packet":
    let nodes = await setupMixNodes(
      5, destReadBehavior = Opt.some((codec: TestCodec, callback: readLp(1024)))
    )
    startAndDeferStop(nodes)
    let sender = nodes[0]
    let dialer = await sender.holdHopStreams(nodes[1 ..^ 1])
    dialer.holdWrites = true

    let conn = sender
      .toConnection(nodes[^1].toMixDestination(), TestCodec, ReplyParams)
      .expect("connection")
    let writing = conn.writeLp(EntryPayload)
    checkUntilTimeout:
      dialer.firstHeld()
    let held = dialer.streams[0]

    let closing = conn.close()
    check await closing.join().withTimeout(1.seconds)
    check await writing.join().withTimeout(1.seconds)
    check:
      writing.failed
      writing.error of LPStreamClosedError
      sender.surbCredsLen == 0
      held.pendingWrites.len == 1

    held.release()
    checkUntilTimeout:
      held.written.len == 1
    check:
      held.cancelledWrites == 0
      not held.isClosed

  for transport in TestTransport:
    asyncTest "send cancelled in write keeps its packet whole over " & $transport:
      let nodes = await setupMixNodes(1, transport = transport)
      startAndDeferStop(nodes)
      let sender = nodes[0]
      let (hopSwitch, hop) = await startStallingHop(transport)
      defer:
        hop.release()
        await hopSwitch.stop()
      let hopId = hopSwitch.peerInfo.peerId
      let hopAddr = hopSwitch.peerInfo.addrs[0]
      var big = newSeq[byte](BigPacketLen)
      for i in 0 ..< big.len:
        big[i] = byte(i mod 251)

      # The hop takes the start of the first frame and then reads nothing, so
      # the rest of the packet waits in the muxer. Mplex kept the packet whole
      # on the base too, so that case only guards against a regression.
      let first = sender.sendCoverPacket(hopId, hopAddr, big)
      check await hop.prefixRead.wait().withTimeout(10.seconds)
      check sender.hopWrites.len == 1
      let second = sender.sendCoverPacket(hopId, hopAddr, @[2.byte])
      first.cancelSoon()
      check await first.join().withTimeout(1.seconds)
      check:
        first.cancelled
        not second.finished
        sender.hopWrites.len == 1

      hop.release()
      let sent = await second.wait(30.seconds)
      let expected = coverFrames(big) & coverFrames(@[2.byte])
      checkUntilTimeout:
        hop.streams.len > 0 and hop.streams[0].len >= expected.len
      let whole = hop.streams.len == 1 and hop.streams[0] == expected
      let streams = outgoingMixStreams(sender.switch)
      check:
        sent.isOk
        whole
        hop.failures.len == 0
        streams.len == 1
        streams.allIt(it.objName == StreamName[transport])

  for transport in TestTransport:
    asyncTest "stalled stream over " & $transport & " recovers on a new connection":
      let nodes = await setupMixNodes(1, transport = transport)
      startAndDeferStop(nodes)
      let sender = nodes[0]
      let (hopSwitch, hop) = await startStallingHop(transport)
      defer:
        hop.release()
        await hopSwitch.stop()
      let hopId = hopSwitch.peerInfo.peerId
      let hopAddr = hopSwitch.peerInfo.addrs[0]
      let big = newSeq[byte](BigPacketLen)

      # The hop reads nothing more from its first stream. On Mplex that also
      # stops the TCP connection.
      let first = sender.sendCoverPacket(hopId, hopAddr, big)
      check await hop.prefixRead.wait().withTimeout(10.seconds)
      check sender.hopWrites.len == 1
      let stream = toSeq(sender.hopWrites.keys)[0]
      let packet = newSeq[byte](4096)
      let fit = WaitingBytesLimit div coverWrite(packet).len
      let waiting =
        toSeq(1 .. fit).mapIt(sender.sendCoverPacket(hopId, hopAddr, packet))
      checkUntilTimeout:
        sender.waitingWrites(stream) == fit

      let stalled = stream.getWrapped()
      sender.ageHopGate(stream)
      let beyond = await sender.sendCoverPacket(hopId, hopAddr, packet).wait(5.seconds)
      await allFutures(waiting).wait(5.seconds)
      check:
        beyond.isErr
        beyond.error.contains("stalled")
        waiting.allIt(it.read().isErr)
        stalled.closed

      # The one retry of the first send can still meet the closing connection
      # before the switch drops it, so its result is not checked.
      check await first.join().withTimeout(30.seconds)
      checkUntilTimeout:
        sender.switch.connManager.getConnections().getOrDefault(hopId).allIt(
          it.connection != stalled
        )

      # A new send goes out on a new connection, and the hop reads it.
      let small = @[3.byte]
      let sent = await sender.sendCoverPacket(hopId, hopAddr, small).wait(10.seconds)
      checkUntilTimeout:
        hop.streams.len >= 2 and coverFrames(small)[^1] in hop.streams[^1]
      check:
        sent.isOk
        hop.connections[^1] != hop.connections[0]

  for transport in TestTransport:
    asyncTest "exchanges over " & $transport & " keep one sender stream for each hop":
      let echoProto = EchoProtocol.new()
      let nodes = await setupMixNodes(
        5,
        destReadBehavior = Opt.some((codec: echoProto.codec, callback: readLp(1024))),
        transport = transport,
      )
      nodes[^1].switch.mount(echoProto)
      startAndDeferStop(nodes)
      let sender = nodes[0]
      let destination = nodes[^1].toMixDestination()
      await exchange(sender, destination, echoProto.codec, 1)
      let before = outgoingMixStreams(sender.switch)
      for value in 2'u8 .. 4'u8:
        await exchange(sender, destination, echoProto.codec, value)
      let after = outgoingMixStreams(sender.switch)
      check:
        before.len > 0
        before.allIt(it in after)
        after.allIt(it.objName == StreamName[transport])
        after.mapIt(it.peerId).deduplicate().len == after.len
