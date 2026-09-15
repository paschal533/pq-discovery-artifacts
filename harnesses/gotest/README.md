# go-ethereum ENR decode behaviour

Runs claim C-06a (CLAIMS.md) instead of reading it: does go-ethereum lose a whole NODES
response when one record carries an unrecognised identity scheme?

```
go run .
```

Pinned to **go-ethereum v1.17.5** in `go.mod`. Do not float it, the claim is about that
version, and the line numbers cited in COEXISTENCE.md §4 are that version's.

## Two things that will bite you

**`CGO_ENABLED=0` is required on a stock Windows box.** geth's default secp256k1 is cgo
bound to a vendored libsecp256k1 whose headers are not in the module zip, so the build
fails on a missing `secp256k1_recovery.h`. With cgo off, `crypto/signature_nocgo.go`
selects the pure-Go btcec path, which is what this test wants anyway, it only signs and
verifies records.

**Module fetch may fail with `lookup sum.golang.org: no such host`** while the system
resolver answers fine. `GODEBUG=netdns=cgo` fixed it here. Do **not** reach for
`GOSUMDB=off`: checksum verification stayed on for the results recorded in COEXISTENCE.md,
and turning it off would weaken the provenance of a dependency the claim rests on.

## What it does

Builds a real signed `v4` record, then rewrites the RLP string `"v4"` to `"v5"`. Both are
two bytes encoding as `0x82 'v' '4'`, so the rewrite is length-preserving: every length
prefix stays correct and the record remains well-formed RLP. Only the scheme changes. The
signature stops matching, which is irrelevant here, the question is whether decoding
survives, and in geth decoding never verifies.

The message-level check drives `v5wire.DecodeMessage(v5wire.NodesMsg, body)`, geth's own
exported decoder, so it sits at the same layer as Rust's `Message::decode` and nim-eth's
`decodeMessage`. The poisoned record is deliberately the **last** of four, so the first
three were already parsed when it is reached.

Sibling harnesses, same substitution, same layer: `../discv5/examples/` (Rust),
`../nimtest/` (nim-eth).
