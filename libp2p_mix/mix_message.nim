# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronicles, results
import stew/[byteutils, leb128]
import libp2p/protobuf/minprotobuf
import libp2p/utils/sequninit

type ReadMethod* = enum
  ReadExactly
  ReadLp
  ReadLine

type MixMessage* = object
  message*: seq[byte]
  codec*: string
  readMethod*: ReadMethod
  readLimit*: int
  readLineSep*: string

proc init*(
    T: typedesc[MixMessage],
    message: openArray[byte],
    codec: string,
    readMethod: ReadMethod = ReadExactly,
    readLimit: int = 0,
    readLineSep: string = "",
): T =
  return T(
    message: @message,
    codec: codec,
    readMethod: readMethod,
    readLimit: readLimit,
    readLineSep: readLineSep,
  )

proc serialize*(mixMsg: MixMessage): seq[byte] =
  let codecLenBytes = toBytes(mixMsg.codec.len.uint64, Leb128)
  doAssert codecLenBytes.len <= 2, "serialization failed: codec length exceeds 2 bytes"

  let readLimitBytes = toBytes(mixMsg.readLimit.uint64, Leb128)
  doAssert readLimitBytes.len <= 2, "serialization failed: readLimit exceeds 2 bytes"

  var totalLen = codecLenBytes.len + mixMsg.codec.len + 1 + readLimitBytes.len + mixMsg.message.len
  if mixMsg.readMethod == ReadLine:
    let sepLenBytes = toBytes(mixMsg.readLineSep.len.uint64, Leb128)
    doAssert sepLenBytes.len <= 2, "serialization failed: separator length exceeds 2 bytes"
    totalLen += sepLenBytes.len + mixMsg.readLineSep.len

  var buf = newSeqUninit[byte](totalLen)
  var offset = 0

  buf[offset ..< offset + codecLenBytes.len] = codecLenBytes.toOpenArray()
  offset += codecLenBytes.len

  buf[offset ..< offset + mixMsg.codec.len] = mixMsg.codec.toBytes()
  offset += mixMsg.codec.len

  buf[offset] = mixMsg.readMethod.byte
  offset += 1

  buf[offset ..< offset + readLimitBytes.len] = readLimitBytes.toOpenArray()
  offset += readLimitBytes.len

  if mixMsg.readMethod == ReadLine:
    let sepLenBytes = toBytes(mixMsg.readLineSep.len.uint64, Leb128)
    buf[offset ..< offset + sepLenBytes.len] = sepLenBytes.toOpenArray()
    offset += sepLenBytes.len
    buf[offset ..< offset + mixMsg.readLineSep.len] = mixMsg.readLineSep.toBytes()
    offset += mixMsg.readLineSep.len

  buf[offset ..< buf.len] = mixMsg.message
  buf

proc deserialize*(
    T: typedesc[MixMessage], data: openArray[byte]
): Result[MixMessage, string] =
  if data.len == 0:
    return err("deserialization failed: data is empty")

  # Parse codec length
  let codecLenParsed = uint16.fromBytes(data, Leb128)
  if codecLenParsed.len <= 0:
    return err("deserialization failed: invalid codec length")
  let codecLen = codecLenParsed.val.int
  var offset = codecLenParsed.len.int

  if data.len < offset + codecLen:
    return err("deserialization failed: not enough data for codec")

  let codec = string.fromBytes(data[offset ..< offset + codecLen])
  offset += codecLen

  if data.len < offset + 1:
    return err("deserialization failed: not enough data for readMethod")
  if data[offset] > byte(high(ReadMethod)):
    return err("deserialization failed: invalid readMethod")
  let readMethod = ReadMethod(data[offset])
  offset += 1

  if data.len < offset + 1:
    return err("deserialization failed: not enough data for readLimit")
  let readLimitParsed = uint16.fromBytes(data[offset .. ^1], Leb128)
  if readLimitParsed.len <= 0:
    return err("deserialization failed: invalid readLimit")
  let readLimit = readLimitParsed.val.int
  offset += readLimitParsed.len.int

  var readLineSep = ""
  if readMethod == ReadLine:
    if data.len < offset + 1:
      return err("deserialization failed: not enough data for separator length")
    let sepLenParsed = uint16.fromBytes(data[offset .. ^1], Leb128)
    if sepLenParsed.len <= 0:
      return err("deserialization failed: invalid separator length")
    let sepLen = sepLenParsed.val.int
    offset += sepLenParsed.len.int
    if data.len < offset + sepLen:
      return err("deserialization failed: not enough data for separator")
    readLineSep = string.fromBytes(data[offset ..< offset + sepLen])
    offset += sepLen

  if data.len < offset:
    return err("deserialization failed: not enough data for message")
  let message = data[offset ..< data.len]

  ok(T(
    message: message,
    codec: codec,
    readMethod: readMethod,
    readLimit: readLimit,
    readLineSep: readLineSep,
  ))
