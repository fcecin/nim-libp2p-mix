# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results, sequtils, tables
import libp2p/[switch, multiaddress, crypto/secp, peerid]
import libp2p_mix
import libp2p_mix/[mix_protocol, delay_strategy]
import ../tools/[lifecycle, unittest, crypto, peer_source]
import ../utils

proc setupHostNodes(count: int): seq[MixProtocol] =
  ## Create and mount one node for each count, each with a host store. Does not
  ## start them.
  var nodes: seq[MixProtocol]
  for _ in 0 ..< count:
    let info = MixNodeInfo.generateRandom(0, rng())
    let sw = createSwitch(info.multiAddr, Opt.some(info.libp2pPrivKey))
    let source = HostPeerSource.new(allowAllAddresses = true)
    let proto = MixProtocol.new(
      info,
      sw,
      brokerCtx = source.brokerCtx,
      delayStrategy = Opt.some(DelayStrategy(NoSamplingDelayStrategy.new(rng()))),
    )
    let echo = EchoProtocol.new()
    sw.mount(echo)
    proto.registerDestReadBehavior(echo.codec, readLp(1024))
    sw.mount(proto)
    nodes.add(proto)
  nodes

proc populate(nodes: seq[MixProtocol]) =
  for node in nodes:
    node.setLocalMultiAddr(node.switch.peerInfo.addrs[0]).expect("bound address")
  let infos = nodes.mapIt(it.localMixPubInfo())
  for node in nodes:
    var bad = infos[0]
    bad.multiAddr = MultiAddress.init("/ip6/::1/tcp/1").get()
    # The host owns its store. The test updates one peer at a time.
    var records: Table[PeerId, MixPubInfo]
    for info in infos:
      records[info.peerId] = info
      testPeerSource(node.brokerCtx).updatePeer(info)
    testPeerSource(node.brokerCtx).updatePeer(bad)
    # Store the valid record of that peer again after the bad address.
    testPeerSource(node.brokerCtx).updatePeer(records[bad.peerId])

suite "Host-owned mix view":
  asyncTeardown:
    checkTrackers()

  asyncTest "a fixed exit needs only its actual intermediates, including replies":
    let nodes = setupHostNodes(4)
    startAndDeferStop(nodes)
    populate(nodes)
    let echo = EchoProtocol.new()
    let conn = nodes[0]
      .toConnection(
        MixDestination.exitNode(nodes[^1].localMixPubInfo().peerId),
        echo.codec,
        MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(1'u8)),
      )
      .get()
    defer:
      await conn.close()
    let payload = @[1'u8, 2, 3]
    await conn.writeLp(payload).wait(5.seconds)
    check (await conn.readLp(1024).wait(5.seconds)) == payload
    check nodes[0].brokerCtx.peerIds().get().len == 4

  asyncTest "forward-address requests and replies use the same host-owned records":
    let nodes = setupHostNodes(4)
    startAndDeferStop(nodes)
    populate(nodes)
    let (dest, echo) = await setupDestNode(EchoProtocol.new())
    defer:
      await stopDestNode(dest)
    let conn = nodes[0]
      .toConnection(
        dest.toMixDestination(),
        echo.codec,
        MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(1'u8)),
      )
      .get()
    defer:
      await conn.close()
    let payload = @[4'u8, 5, 6]
    await conn.writeLp(payload).wait(5.seconds)
    check (await conn.readLp(1024).wait(5.seconds)) == payload
    check nodes[0].brokerCtx.peerIds().get().len == 4

  asyncTest "cover construction uses host-owned records without membership changes":
    let nodes = setupHostNodes(3)
    startAndDeferStop(nodes)
    populate(nodes)
    let before = nodes[0].brokerCtx.peerIds().get()
    let packet = await nodes[0].buildCoverPacket()
    check packet.isOk
    check nodes[0].brokerCtx.peerIds().get() == before
