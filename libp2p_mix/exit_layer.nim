# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronicles, chronos, metrics, std/sequtils
import libp2p/builders
import libp2p/protobuf/minprotobuf
import libp2p/stream/connection
import libp2p/varint
import libp2p/utils/sequninit
import stew/byteutils
import ./[mix_message, mix_metrics, reply_connection, serialization, multiaddr]

when defined(libp2p_mix_experimental_exit_is_dest):
  import std/enumerate
  import ./exit_connection

type OnReplyDialer* =
  proc(surb: SURB, message: seq[byte]) {.async: (raises: [CancelledError]).}

type ExitLayer* = object
  switch: Switch
  onReplyDialer: OnReplyDialer

proc init*(
    T: typedesc[ExitLayer],
    switch: Switch,
    onReplyDialer: OnReplyDialer,
): T =
  ExitLayer(switch: switch, onReplyDialer: onReplyDialer)

proc replyDialerCbFactory(self: ExitLayer): MixReplyDialer =
  return proc(
      surbs: seq[SURB], msg: seq[byte]
  ): Future[void] {.async: (raises: [CancelledError, LPStreamError]).} =
    let respFuts = surbs.mapIt(self.onReplyDialer(it, msg))
    await allFutures(respFuts)

proc reply(
    self: ExitLayer, surbs: seq[SURB], response: seq[byte]
) {.async: (raises: [CancelledError]).} =
  if surbs.len == 0:
    return

  let replyConn = MixReplyConnection.new(surbs, self.replyDialerCbFactory())
  defer:
    await replyConn.close()
  try:
    await replyConn.write(response)
  except LPStreamError as exc:
    error "could not reply", description = exc.msg
    mix_messages_error.inc(labelValues = ["ExitLayer", "REPLY_FAILED"])

when defined(libp2p_mix_experimental_exit_is_dest):
  proc runHandler(
      self: ExitLayer, mixMsg: MixMessage, surbs: seq[SURB]
  ) {.async: (raises: [CancelledError]).} =
    let exitConn = MixExitConnection.new(mixMsg.message)
    defer:
      await exitConn.close()

    var hasHandler: bool = false
    for index, handler in enumerate(self.switch.ms.handlers):
      if mixMsg.codec in handler.protos:
        try:
          hasHandler = true
          await handler.protocol.handler(exitConn, mixMsg.codec)
        except CatchableError as e:
          error "Error during execution of MixProtocol handler: ", err = e.msg

    if not hasHandler:
      error "Handler doesn't exist", codec = mixMsg.codec
      return

    if surbs.len != 0:
      let response = exitConn.getResponse()
      await self.reply(surbs, response)

proc fwdRequest(
    self: ExitLayer,
    mixMsg: MixMessage,
    destination: Hop,
    surbs: seq[SURB],
) {.async: (raises: [CancelledError]).} =
  # If dialing destination fails, no response is returned to
  # the sender, so, flow can just end here. Only log errors
  # for now
  # https://github.com/vacp2p/mix/issues/86

  if destination == Hop():
    error "no destination available"
    mix_messages_error.inc(labelValues = ["Exit", "NO_DESTINATION"])
    return

  let (destPeerId, destAddr) = destination.get().bytesToMultiAddr().valueOr:
      error "Failed to convert bytes to multiaddress", err = error
      mix_messages_error.inc(labelValues = ["Exit", "INVALID_DEST"])
      return

  var response: seq[byte]
  try:
    let destConn = await self.switch.dial(destPeerId, @[destAddr], mixMsg.codec)
    defer:
      await destConn.close()
    await destConn.write(mixMsg.message)

    if surbs.len != 0:
      case mixMsg.readMethod
      of ReadExactly:
        let buf = newSeqUninit[byte](mixMsg.readLimit)
        await destConn.readExactly(addr buf[0], mixMsg.readLimit)
        response = buf
      of ReadLp:
        let rawResponse = await destConn.readLp(mixMsg.readLimit)
        let vbytes = PB.toBytes(rawResponse.len.uint64)
        response = newSeqUninit[byte](rawResponse.len + vbytes.len)
        response[0 ..< vbytes.len] = vbytes.toOpenArray()
        response[vbytes.len ..< response.len] = rawResponse
      of ReadLine:
        let rawResponse = await destConn.readLine(mixMsg.readLimit, mixMsg.readLineSep)
        response = (rawResponse & mixMsg.readLineSep).toBytes()
  except LPStreamError as exc:
    error "Stream error while writing to next hop: ", err = exc.msg
    mix_messages_error.inc(labelValues = ["ExitLayer", "LPSTREAM_ERR"])
  except DialFailedError as exc:
    error "Failed to dial next hop: ", err = exc.msg
    mix_messages_error.inc(labelValues = ["ExitLayer", "DIAL_FAILED"])
  except CancelledError as exc:
    raise exc

  await self.reply(surbs, response)

proc onMessage*(
    self: ExitLayer,
    mixMsg: MixMessage,
    destination: Hop,
    surbs: seq[SURB],
) {.async: (raises: [CancelledError]).} =
  when defined(libp2p_mix_experimental_exit_is_dest):
    if destination == Hop():
      trace "onMessage - exit is destination", codec = mixMsg.codec, message = mixMsg.message
      await self.runHandler(mixMsg, surbs)
    else:
      trace "onMessage - exit is not destination", codec = mixMsg.codec, message = mixMsg.message
      await self.fwdRequest(mixMsg, destination, surbs)
  else:
    await self.fwdRequest(mixMsg, destination, surbs)
