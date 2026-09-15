## Does nim-eth behave the way COEXISTENCE.md says it does?
##
## Findings C1 and C2 for Waku were established by reading nim-eth's source, not by
## running it. This executes it. The claims under test:
##
##   C1  an unrecognised identity scheme is a DECODE failure, not a verify failure
##       (enr.nim, the `case id` block ending `return err("Unknown Identity Scheme")`)
##   C2  read*(rlp, Record) turns that Result into a raised RlpError, which the
##       message decoder catches for the whole message
##
## Method matches the Rust `poison.rs`: take a real, valid, signed record and
## substitute the RLP string "v4" with "v5". Both are two bytes, so every length
## prefix stays correct and the bytes remain well-formed RLP. Only the scheme changes.

import std/[strutils, sequtils, net]
import eth/enr/enr
import eth/common/keys
import eth/rlp
import eth/p2p/discoveryv5/[messages, messages_encoding]

proc toV5(raw: seq[byte]): seq[byte] =
  ## Rewrite the RLP-encoded string "v4" (0x82 'v' '4') to "v5". Length-preserving.
  result = raw
  for i in 0 ..< result.len - 2:
    if result[i] == 0x82'u8 and result[i+1] == byte('v') and result[i+2] == byte('4'):
      result[i+2] = byte('5')
      return
  raise newException(ValueError, "no RLP-encoded \"v4\" found")

proc makeRecord(seqNum: uint64, port: int): Record =
  let rng = newRng()
  let pk = PrivateKey.random(rng[])
  Record.init(seqNum, pk, udpPort = Opt.some(Port(port))).expect("valid record")

when isMainModule:
  echo "nim-eth ENR decode behaviour"
  echo "============================"

  let rec = makeRecord(1, 9000)
  let raw = rec.raw
  echo "  built a v4 record, ", raw.len, " bytes"

  # 1. control: the untouched record decodes
  let ok = Record.fromBytes(raw)
  echo "  1. valid v4 record            -> ", (if ok.isOk: "decodes" else: "REJECTED: " & $ok.error)

  # 2. the same record with id = "v5"
  let v5raw = toV5(raw)
  doAssert v5raw.len == raw.len, "substitution changed the length"
  let bad = Record.fromBytes(v5raw)
  echo "  2. same record, id = \"v5\"     -> ",
       (if bad.isOk: "decodes (UNEXPECTED)" else: "rejected: " & $bad.error)

  # 3. does the rejection happen at decode, before any signature check?
  #    A record whose signature we also corrupt should give the SAME error if the
  #    scheme is checked first.
  var sigCorrupt = v5raw
  sigCorrupt[^1] = sigCorrupt[^1] xor 0x01'u8
  let bad2 = Record.fromBytes(sigCorrupt)
  echo "  3. id = \"v5\" AND bad signature -> ",
       (if bad2.isOk: "decodes (UNEXPECTED)" else: "rejected: " & $bad2.error)
  echo "     (same error as 2 means the scheme is checked before the signature)"

  # 4. the C2 claim: read*(rlp, Record) raises, rather than returning a Result
  echo ""
  echo "  4. does rlp.read(Record) RAISE on the v5 record?"
  var raised = false
  var msg = ""
  try:
    var r = rlpFromBytes(v5raw)
    discard r.read(Record)
  except RlpError as e:
    raised = true
    msg = e.msg
  except CatchableError as e:
    raised = true
    msg = "(" & $e.name & ") " & e.msg
  echo "     raised: ", raised, (if raised: "  -> " & msg else: "")
  echo ""
  if raised:
    echo "  C1 and C2 confirmed by execution: an unrecognised identity scheme is"
    echo "  rejected during decode, and the RLP reader converts that into a raised"
    echo "  exception. messages_encoding.nim wraps the whole message body in"
    echo "  `try ... except RlpError`, so one such record discards the message."
  else:
    echo "  C2 NOT confirmed: read(Record) did not raise. COEXISTENCE.md needs revising."

  # ------------------------------------------------------------------
  # 5. the claim that actually matters for migration: one unrecognised
  #    record discards the WHOLE NODES message, including the records
  #    that decoded perfectly well.
  #
  #    decodeMessage puts `of nodes: rlp.decode(message.nodes)` inside a
  #    single `try ... except RlpError, ValueError: return err(...)`
  #    (messages_encoding.nim:104-116). Reading that is not the same as
  #    running it, so run it. The LAST record is the poisoned one, which
  #    means the first three were already parsed when it fails.
  # ------------------------------------------------------------------
  echo ""
  echo "  5. a NODES message carrying 4 records, the last one \"v5\":"

  var enrs: seq[Record]
  for i in 0 ..< 4:
    enrs.add(makeRecord(1, 9100 + i))
  let body = encodeMessage(
    NodesMessage(total: 1, enrs: enrs), RequestId(id: @[1'u8, 2, 3, 4]))

  let control = decodeMessage(body)
  echo "     control, all v4          -> ",
       (if control.isOk: "decodes, " & $control.value.nodes.enrs.len & " records"
        else: "REJECTED: " & $control.error)

  # rewrite the 4th "v4" in the message body, i.e. the last record's scheme
  var poisoned = body
  var seen = 0
  for i in 0 ..< poisoned.len - 2:
    if poisoned[i] == 0x82'u8 and poisoned[i+1] == byte('v') and
       poisoned[i+2] == byte('4'):
      inc seen
      if seen == 4:
        poisoned[i+2] = byte('5')
        break
  doAssert seen == 4, "expected 4 identity schemes, found " & $seen
  doAssert poisoned.len == body.len

  let got = decodeMessage(poisoned)
  if got.isOk:
    echo "     last record \"v5\"         -> decodes, ",
         got.value.nodes.enrs.len, " records  (C2 NOT confirmed)"
  else:
    echo "     last record \"v5\"         -> WHOLE MESSAGE REJECTED: ", $got.error
    echo ""
    echo "     3 of the 4 records were valid, already parsed, and are lost."
    echo "     The caller is told only \"", $got.error, "\" - not which record,"
    echo "     not that an identity scheme was the reason."
