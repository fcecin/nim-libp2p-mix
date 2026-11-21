# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/[importutils, strutils, tables]
import chronos, metrics, results, strformat
import
  libp2p/
    [protocols/ping, peerid, multiaddress, switch, builders, crypto/crypto, crypto/secp]
import libp2p/[connmanager, dialer, muxers/muxer, peeraddrpolicy, stream/connection]
import libp2p_mix
import libp2p_mix/mix_protocol
import libp2p_mix/curve25519
import libp2p_mix/delay_strategy
import libp2p_mix/mix_metrics

import ./tools/crypto
import ./[mock_mix, spam_protection_impl]

type TestTransport* {.pure.} = enum
  ## The transport and the muxer of a test switch.
  TcpMplex
  TcpYamux
  Quic

proc createSwitch*(
    multiAddr: MultiAddress = MultiAddress.init("/ip4/0.0.0.0/tcp/0").tryGet(),
    libp2pPrivKey: Opt[SkPrivateKey] = Opt.none(SkPrivateKey),
    transport = TestTransport.TcpMplex,
): Switch =
  let privKey = PrivateKey(
    scheme: Secp256k1, skkey: libp2pPrivKey.valueOr(SkKeyPair.random(rng()).seckey)
  )
  let builder =
    SwitchBuilder.new().withRng(rng()).withPrivateKey(privKey).withAddress(multiAddr)
  case transport
  of TestTransport.TcpMplex:
    builder.withTcpTransport().withMplex().withNoise().build()
  of TestTransport.TcpYamux:
    builder.withTcpTransport().withYamux().withNoise().build()
  of TestTransport.Quic:
    builder.withQuicTransport().build()

proc quicAddress(tcpAddr: MultiAddress): MultiAddress =
  ## The QUIC-v1 address on loopback with the port of `tcpAddr`.
  let text =
    ($tcpAddr).replace("/ip4/0.0.0.0/", "/ip4/127.0.0.1/").replace("/tcp/", "/udp/")
  MultiAddress.init(text & "/quic-v1").tryGet()

proc setupMixNode[T: MixProtocol](
    mixNodeInfo: MixNodeInfo,
    switch: Switch,
    destReadBehavior: Opt[tuple[codec: string, callback: DestReadBehavior]],
    spamProtectionRateLimit: Opt[int],
    delayStrategy: Opt[DelayStrategy] = Opt.none(DelayStrategy),
    hopBackoff: Duration = DefaultHopBackoff,
    hopAddressPolicy: PeerAddressPolicy = defaultAddressPolicy,
): T =
  let spamProtection =
    if spamProtectionRateLimit.isSome():
      Opt.some(
        SpamProtection(newRateLimitSpamProtection(spamProtectionRateLimit.get()))
      )
    else:
      Opt.none(SpamProtection)
  let actualDelayStrategy = delayStrategy.valueOr:
    if spamProtectionRateLimit.isSome():
      DelayStrategy(SpamProtectionDelayStrategy.new(DefaultMeanDelay, rng()))
    else:
      DelayStrategy(NoSamplingDelayStrategy.new(rng()))

  let proto = T.new(
    mixNodeInfo,
    switch,
    spamProtection = spamProtection,
    delayStrategy = Opt.some(actualDelayStrategy),
    hopBackoff = hopBackoff,
    hopAddressPolicy = hopAddressPolicy,
  )

  if destReadBehavior.isSome():
    let (codec, callback) = destReadBehavior.get()
    proto.registerDestReadBehavior(codec, callback)

  switch.mount(proto)
  proto

proc setupMixNodes*(
    numNodes: int,
    destReadBehavior = Opt.none(tuple[codec: string, callback: DestReadBehavior]),
    spamProtectionRateLimit = Opt.none(int),
    delayStrategy = Opt.none(DelayStrategy),
    hopBackoff: Duration = DefaultHopBackoff,
    hopAddressPolicy: PeerAddressPolicy = defaultAddressPolicy,
    transport = TestTransport.TcpMplex,
): Future[seq[MixProtocol]] {.async.} =
  var nodes: seq[MixProtocol] = @[]
  var nodeInfos = MixNodeInfo.generateRandomMany(numNodes, rng())
  if transport == TestTransport.Quic:
    for info in nodeInfos.mitems:
      info.multiAddr = quicAddress(info.multiAddr)
  for mixNodeInfo in nodeInfos:
    let switch = createSwitch(
      mixNodeInfo.multiAddr, Opt.some(mixNodeInfo.libp2pPrivKey), transport
    )
    let mixNode = setupMixNode[MixProtocol](
      mixNodeInfo, switch, destReadBehavior, spamProtectionRateLimit, delayStrategy,
      hopBackoff, hopAddressPolicy,
    )
    mixNode.nodePool.add(nodeInfos.includeAllExcept(mixNodeInfo))
    nodes.add(mixNode)

  nodes

proc setupMixNodesWithMock*(
    numNodes: int,
    destReadBehavior = Opt.none(tuple[codec: string, callback: DestReadBehavior]),
    delayStrategy = Opt.none(DelayStrategy),
): Future[tuple[nodes: seq[MixProtocol], mock: MockMixProtocol]] {.async.} =
  ## Like setupMixNodes, but the first node is a MockMixProtocol.
  var nodes: seq[MixProtocol] = @[]

  let nodeInfos = MixNodeInfo.generateRandomMany(numNodes, rng())

  let mockMixNodeInfo = nodeInfos[0]
  let mockSwitch =
    createSwitch(mockMixNodeInfo.multiAddr, Opt.some(mockMixNodeInfo.libp2pPrivKey))

  let mock = setupMixNode[MockMixProtocol](
    mockMixNodeInfo, mockSwitch, destReadBehavior, Opt.none(int), delayStrategy
  )
  mock.nodePool.add(nodeInfos.includeAllExcept(mockMixNodeInfo))
  nodes.add(mock)

  for index in 1 ..< numNodes:
    let mixNodeInfo = nodeInfos[index]
    let switch =
      createSwitch(mixNodeInfo.multiAddr, Opt.some(mixNodeInfo.libp2pPrivKey))
    let mixNode = setupMixNode[MixProtocol](
      mixNodeInfo, switch, destReadBehavior, Opt.none(int), delayStrategy
    )
    mixNode.nodePool.add(nodeInfos.includeAllExcept(mixNodeInfo))
    nodes.add(mixNode)

  (nodes, mock)

proc setupDestNode*[T: LPProtocol](
    proto: T
): Future[tuple[switch: Switch, proto: T]] {.async.} =
  let switch = createSwitch()
  switch.mount(proto)
  await switch.start()
  return (switch, proto)

proc stopDestNode*(switch: Switch) {.async.} =
  await switch.stop()

proc toMixDestination*(switch: Switch): MixDestination =
  MixDestination.init(switch.peerInfo.peerId, switch.peerInfo.addrs[0])

proc toMixDestination*(node: MixProtocol): MixDestination =
  node.switch.toMixDestination()

###

const NoReplyProtocolCodec = "/test/1.0.0"

type ReceivedMessage* = object
  connPeerId*: PeerId
  data*: seq[byte]

type NoReplyProtocol* = ref object of LPProtocol
  receivedMessages*: AsyncQueue[ReceivedMessage]

proc new*(T: typedesc[NoReplyProtocol]): NoReplyProtocol =
  let nrProto = NoReplyProtocol()
  nrProto.receivedMessages = newAsyncQueue[ReceivedMessage]()

  proc handler(conn: Connection, proto: string) {.async: (raises: [CancelledError]).} =
    try:
      let buffer = await conn.readLp(1024)
      await nrProto.receivedMessages.put(
        ReceivedMessage(connPeerId: conn.peerId, data: buffer)
      )
    except LPStreamError:
      discard
    finally:
      await conn.close()

  nrProto.handler = handler
  nrProto.codec = NoReplyProtocolCodec
  nrProto

type SilentProtocol* = ref object of LPProtocol
  ## Reads one message then holds the stream open without answering, so the
  ## exit layer never gets a response to send back. Unlike NoReplyProtocol,
  ## which closes and therefore makes the exit reply with an empty payload.
  ##
  ## Call `release` before stopping the destination node, otherwise shutdown
  ## blocks on the parked handler.
  receivedMessages*: AsyncQueue[ReceivedMessage]
  hold: Future[void]

proc new*(T: typedesc[SilentProtocol], codec: string): SilentProtocol =
  let proto = SilentProtocol(
    receivedMessages: newAsyncQueue[ReceivedMessage](), hold: newFuture[void]()
  )

  proc handler(
      conn: Connection, protoId: string
  ) {.async: (raises: [CancelledError]).} =
    try:
      let buffer = await conn.readLp(1024)
      await proto.receivedMessages.put(
        ReceivedMessage(connPeerId: conn.peerId, data: buffer)
      )
      await proto.hold
    except CancelledError as e:
      raise e
    except CatchableError:
      discard
    finally:
      await conn.close()

  proto.handler = handler
  proto.codec = codec
  proto

proc release*(proto: SilentProtocol) =
  if not proto.hold.finished:
    proto.hold.complete()

const EchoCodec = "/echo/test/1.0.0"
const EchoMaxReadLen* = 1024

type EchoProtocol* = ref object of LPProtocol

proc new*(T: typedesc[EchoProtocol]): EchoProtocol =
  let echoProto = EchoProtocol()

  proc handler(conn: Connection, proto: string) {.async: (raises: [CancelledError]).} =
    try:
      let request = await conn.readLp(EchoMaxReadLen)
      await conn.writeLp(request)
    except CancelledError as e:
      raise e
    except CatchableError as e:
      raiseAssert "Echo handler error: " & e.msg
    finally:
      await conn.close()

  echoProto.handler = handler
  echoProto.codec = EchoCodec
  echoProto

###

type FixedDelayStrategy* = ref object of DelayStrategy
  delay*: Delay

method generateForEntry*(self: FixedDelayStrategy): Delay =
  self.delay

method generateForIntermediate*(self: FixedDelayStrategy, encodedDelay: Delay): Delay =
  self.delay

type HoldingServer* = ref object
  ## A TCP server that accepts and never answers, so a dial to it stays in its
  ## handshake.
  server: StreamServer
  connections*: seq[StreamTransport]
  acceptor: Future[void]

proc new*(T: typedesc[HoldingServer]): T =
  let hold = T(server: createStreamServer(initTAddress("127.0.0.1:0")))
  proc acceptLoop() {.async.} =
    while true:
      hold.connections.add(await hold.server.accept())

  hold.acceptor = acceptLoop()
  hold

proc address*(hold: HoldingServer): MultiAddress =
  MultiAddress.init(hold.server.localAddress()).expect("address")

proc close*(hold: HoldingServer) {.async.} =
  await hold.acceptor.cancelAndWait()
  for connection in hold.connections:
    await connection.closeWait()
  await hold.server.closeWait()

privateAccess(MixProtocol)
privateAccess(typeof(MixProtocol().hopGates.getOrDefault(nil)))

const WaitingBytesLimit* = 256 * 1024 ## The `MaxWaitingHopBytes` of the mix protocol.

type
  HoldingConnection* = ref object of Connection
    ## The connection under a `HoldingStream`. A close only counts in `closes`.
    closes*: int

  HoldingStream* = ref object of Connection
    ## A hop stream with no connection. While `hold` is true, a write waits
    ## until the test releases or fails it, as on a full send window. A read
    ## waits until the stream closes, and then it fails with EOF. When
    ## `closing` is set, a close waits for it.
    hold*: bool
    pendingWrites*: seq[Future[void].Raising([CancelledError, LPStreamError])]
    cancelledWrites*: int
    written*: seq[seq[byte]]
    closing*: Future[void].Raising([CancelledError])
    wasReset*: bool
    connection*: HoldingConnection
    pendingRead: Future[void].Raising([CancelledError, LPStreamError])

  HoldingDialer* = ref object of Dialer
    ## Opens a `HoldingStream` for each dial, with `holdWrites` as its `hold`.
    ## With `instant`, a dial is complete when it returns. With `failDials`, a
    ## dial fails. With `endStreams`, each new stream is at its end, as when the
    ## next hop closes it at once.
    holdWrites*: bool
    instant*: bool
    failDials*: bool
    endStreams*: bool
    streams*: seq[HoldingStream]

method write(
    self: HoldingStream, msg: sink seq[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError]).} =
  if self.isClosed:
    raise newLPStreamClosedError()
  if self.hold:
    let pending =
      Future[void].Raising([CancelledError, LPStreamError]).init("HoldingStream.write")
    self.pendingWrites.add(pending)
    try:
      await pending
    except CancelledError as e:
      inc self.cancelledWrites
      raise e
    finally:
      let index = self.pendingWrites.find(pending)
      if index != -1:
        self.pendingWrites.del(index)
  self.written.add(msg)

method readOnce(
    self: HoldingStream, pbytes: pointer, nbytes: int
): Future[int] {.async: (raises: [CancelledError, LPStreamError]).} =
  if self.isClosed:
    raise newLPStreamEOFError()
  self.pendingRead =
    Future[void].Raising([CancelledError, LPStreamError]).init("HoldingStream.readOnce")
  await self.pendingRead
  return 0

method closeImpl(self: HoldingStream) {.async: (raises: []).} =
  if not self.closing.isNil:
    await noCancel self.closing
  if not self.pendingRead.isNil and not self.pendingRead.finished:
    self.pendingRead.fail(newLPStreamEOFError())
  await procCall Connection(self).closeImpl()

method closeImpl(self: HoldingConnection) {.async: (raises: []).} =
  inc self.closes

method getWrapped(self: HoldingStream): Connection =
  self.connection

method resetImpl(self: HoldingStream) {.async: (raises: []).} =
  self.wasReset = true
  await self.closeImpl()

method dial(
    self: HoldingDialer,
    peerId: PeerId,
    addrs: seq[MultiAddress],
    protos: seq[string],
    forceDial = false,
): Future[Stream] {.async: (raises: [DialFailedError, CancelledError]).} =
  # A dial of the switch waits for the network. A timer wakes an idle event
  # loop, and `stepsAsync` does not.
  if not self.instant:
    await sleepAsync(1.milliseconds)
  if self.failDials:
    raise newException(DialFailedError, "the holding dialer fails its dials")
  let stream = HoldingStream(
    peerId: peerId,
    dir: Direction.Out,
    hold: self.holdWrites,
    connection: HoldingConnection(peerId: peerId, dir: Direction.Out),
  )
  stream.initStream()
  stream.isEof = self.endStreams
  self.streams.add(stream)
  return stream

proc release*(stream: HoldingStream) =
  let pending = stream.pendingWrites
  for write in pending:
    if not write.finished:
      write.complete()

proc endRead*(stream: HoldingStream) =
  ## Ends the reads of `stream`, as when the next hop closes its side. Writes
  ## continue to work.
  stream.isEof = true
  if not stream.pendingRead.isNil and not stream.pendingRead.finished:
    stream.pendingRead.fail(newLPStreamEOFError())

proc failWrites*(stream: HoldingStream, error: ref LPStreamError) =
  let pending = stream.pendingWrites
  for write in pending:
    if not write.finished:
      write.fail(error)

proc holdHopStreams*(
    node: MixProtocol, hops: seq[MixProtocol]
): Future[HoldingDialer] {.async.} =
  ## Connects `node` to each of `hops`, and then makes `node` open a
  ## `HoldingStream` for each dial. With these connections the switch shows
  ## `hops` as connected, so the pool keeps their streams.
  for hop in hops:
    await node.switch.connect(hop.switch.peerInfo.peerId, hop.switch.peerInfo.addrs)
  let switch = node.switch
  let dialer = HoldingDialer(
    HoldingDialer.new(
      switch.peerInfo.peerId, switch.connManager, switch.peerStore, switch.transports,
      switch.ms,
    )
  )
  switch.dialer = dialer
  dialer

proc waitingWrites*(node: MixProtocol, stream: Connection): int =
  ## The writes that wait behind the write in progress on `stream`.
  let gate = node.hopGates.getOrDefault(stream)
  if gate.isNil: 0 else: gate.waiting

proc ageHopGate*(node: MixProtocol, stream: Connection) =
  ## Makes the writes on `stream` look as if they made no progress for an hour.
  node.hopGates[stream].progress = Moment.now() - chronos.hours(1)

proc firstHeld*(dialer: HoldingDialer): bool =
  ## True when `dialer` opened one stream and one write waits on it.
  dialer.streams.len == 1 and dialer.streams[0].pendingWrites.len == 1

proc errorCount*(role, reason: string): float64 =
  ## The count of `mix_messages_error` for `role` and `reason`. 0 before the
  ## label exists.
  try:
    mix_messages_error.value([role, reason])
  except KeyError:
    0.0

proc forwardedCount*(role: string): float64 =
  ## The count of `mix_messages_forwarded` for `role`. 0 before the label exists.
  try:
    mix_messages_forwarded.value([role])
  except KeyError:
    0.0

proc outgoingMixStreams*(switch: Switch): seq[Connection] =
  ## List the open outgoing mix streams of a switch.
  var streams: seq[Connection]
  for _, muxers in switch.connManager.getConnections():
    for mux in muxers:
      for stream in mux.getStreams():
        if stream.dir == Direction.Out and stream.protocol == MixProtocolID and
            not stream.closed:
          streams.add(stream)
  streams
