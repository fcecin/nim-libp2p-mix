# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results, sequtils
import libp2p/[peerid, switch]
import libp2p_mix
import libp2p_mix/mix_protocol
import libp2p_mix/sphinx
import ./tools/[unittest, crypto]
import ./utils

suite "Return path selection and the reply anchor":
  ## `selectReplyHops` picks the intermediary nodes of a return path. The
  ## nodes here are set up and never started: the selection reads the pool.
  var
    nodes {.threadvar.}: seq[MixProtocol]
    sender {.threadvar.}: MixProtocol
    pool {.threadvar.}: seq[PeerId]

  asyncSetup:
    nodes = await setupMixNodes(6)
    sender = nodes[0]
    pool = sender.nodePool.peerIds()

  proc peerId(node: MixProtocol): PeerId =
    node.switch.peerInfo.peerId

  asyncTest "without an anchor, the return path takes two distinct pool nodes, neither the exit nor the destination":
    let exit = nodes[1].peerId()
    let dest = nodes[2].peerId()
    for _ in 0 ..< 20:
      let hops = sender.selectReplyHops(dest, exit, Opt.none(PeerId)).expect("hops")
      check:
        hops.len == PathLength - 1
        hops[0] != hops[1]
        hops.allIt(it in pool)
        exit notin hops
        dest notin hops

  asyncTest "with an anchor, the hop that delivers the reply is the anchor and the other hop is another node":
    let exit = nodes[1].peerId()
    let dest = nodes[2].peerId()
    let anchor = nodes[3].peerId()
    for _ in 0 ..< 20:
      let hops = sender.selectReplyHops(dest, exit, Opt.some(anchor)).expect("hops")
      check:
        hops.len == PathLength - 1
        hops[^1] == anchor
        hops[0] != anchor
        hops[0] in pool
        hops[0] != exit
        hops[0] != dest

  asyncTest "the anchor works with the exit as the destination and the minimum pool":
    ## Exit == destination, and a pool of PathLength + 1 nodes: the exit,
    ## the anchor and two others. One other node is left for the random hop.
    let exit = nodes[1].peerId()
    let anchor = nodes[2].peerId()
    for extra in nodes[5 .. ^1]:
      discard sender.nodePool.remove(extra.peerId())
    check sender.nodePool.len == PathLength + 1
    let hops = sender.selectReplyHops(exit, exit, Opt.some(anchor)).expect("hops")
    check:
      hops[^1] == anchor
      hops[0] in [nodes[3].peerId(), nodes[4].peerId()]

  asyncTest "an anchor that is the exit node is rejected":
    let exit = nodes[1].peerId()
    let dest = nodes[2].peerId()
    let res = sender.selectReplyHops(dest, exit, Opt.some(exit))
    check:
      res.isErr()
      res.error == "reply anchor is the exit node or the destination"

  asyncTest "an anchor that is the destination is rejected":
    let exit = nodes[1].peerId()
    let dest = nodes[2].peerId()
    let res = sender.selectReplyHops(dest, exit, Opt.some(dest))
    check:
      res.isErr()
      res.error == "reply anchor is the exit node or the destination"

  asyncTest "a pool of the exit, the destination and the anchor leaves no node for the other hop":
    let exit = nodes[1].peerId()
    let dest = nodes[2].peerId()
    let anchor = nodes[3].peerId()
    for extra in nodes[4 .. ^1]:
      discard sender.nodePool.remove(extra.peerId())
    check sender.nodePool.len == PathLength
    let res = sender.selectReplyHops(dest, exit, Opt.some(anchor))
    check:
      res.isErr()
      res.error == "not enough mix nodes for a return path"

  asyncTest "an anchor outside the pool is rejected":
    let exit = nodes[1].peerId()
    let dest = nodes[2].peerId()
    let res = sender.selectReplyHops(dest, exit, Opt.some(sender.peerId()))
    check:
      res.isErr()
      res.error == "reply anchor is not in the mix node pool"
