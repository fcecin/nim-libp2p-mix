# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results
import libp2p/[switch, multiaddress]
import libp2p_mix
import libp2p_mix/delay_strategy
import ../tools/[lifecycle, unittest, crypto, peer_source]
import ../utils

proc failedEntry(preconnect: bool) {.async.} =
  let closed = createSwitch()
  await closed.start()
  let closedAddress = closed.peerInfo.addrs[0]
  await closed.stop()
  let (other, receiver) = await setupDestNode(NoReplyProtocol.new())
  defer:
    await stopDestNode(other)
  let info = MixNodeInfo.generateRandom(0, rng())
  let sw = createSwitch(info.multiAddr, Opt.some(info.libp2pPrivKey))
  let source = HostPeerSource.new(allowAllAddresses = true)
  let ctx = source.brokerCtx
  for node in MixNodeInfo.generateRandomMany(3, rng()):
    var candidate = node.toMixPubInfo()
    candidate.multiAddr = closedAddress
    source.updatePeer(candidate)
  let sender = MixProtocol.new(
    info,
    sw,
    brokerCtx = ctx,
    delayStrategy = Opt.some(DelayStrategy(NoSamplingDelayStrategy.new(rng()))),
  )
  sw.mount(sender)
  let nodes = @[sender]
  startAndDeferStop(nodes)
  if preconnect:
    await sw.connect(other.peerInfo.peerId, other.peerInfo.addrs)
  let conn = sender.toConnection(other.toMixDestination(), receiver.codec).get()
  defer:
    await conn.close()
  expect LPStreamError:
    await conn.writeLp(@[1'u8, 2, 3]).wait(5.seconds)
  check source.peerIds().len == 3
  # The library does not update host health state after a failed dial.
  check ctx.peerIds().get().len == 3

suite "Host ownership after transport failure":
  asyncTeardown:
    checkTrackers()

  asyncTest "a failed entry dial preserves host-owned records while online":
    await failedEntry(true)

  asyncTest "a failed entry dial preserves host-owned records with no other connection":
    await failedEntry(false)
