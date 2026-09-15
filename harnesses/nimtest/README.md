# nim-eth ENR decode behaviour

Runs claims C1 and C2 (COEXISTENCE.md §1, §2) instead of reading them: does nim-eth reject
an unrecognised identity scheme at decode, and does one such record discard a whole NODES
message?

```
nim c $(cat .nimpaths) -o:enr_test.exe enr_decode_test.nim
./enr_test.exe
```

## Pinned versions

| | commit | date |
|---|---|---|
| `nim-eth` | `cde1950` | 2026-09-02 |
| `nim-chronicles` | `e1122a0` | 2026-09-11 |
| `nim-secp256k1` | `38b81f5` | 2026-09-03 |
| `nim-stew` | `c75502c` | 2026-08-24 |
| `nim-stint` | `8ae0b5f` | 2026-08-30 |
| `nim-intops` | `d30bd41` | 2026-04-03 |
| Nim | 2.2.10 | Windows amd64 |

The `enr.nim` line numbers cited in COEXISTENCE.md are `cde1950`'s. Two of them had already
drifted from what this project cited earlier: the `else` arm is at **542** (cited as
534-541) and `read*(rlp, Record)` at **637-645** (cited as 637-649). Re-pin before quoting
them anywhere public.

## Why `.nimpaths` exists

nimble's SAT-based dependency solver failed on every one of these packages, so the deps are
vendored by hand under `../nimdeps/` and passed as explicit `--path:` flags. `nim-secp256k1`
additionally needs its git submodule fetched, or the C sources are absent and the link
fails with unresolved `secp256k1_*` symbols.

`.nimpaths` holds absolute paths. If you move the tree, regenerate it.

## What it does

Builds a real signed record via `Record.init`, then rewrites the RLP string `"v4"` to
`"v5"`. Both are two bytes encoding as `0x82 'v' '4'`, so the rewrite is length-preserving:
every length prefix stays correct and the record remains well-formed RLP. Only the scheme
changes.

Case 3 is the one that settles decode-vs-verify ordering: it corrupts the signature *as
well*, and gets the identical error, so the scheme is rejected before any signature check
runs.

Case 5 is the one that matters for migration. It encodes a genuine NODES message with four
records and rewrites the **fourth** record's scheme, so the first three were already parsed
successfully when the fourth raises. `decodeMessage` returns `err("Invalid message
encoding")` and all four are lost.

Sibling harnesses, same substitution, same layer: `../discv5/examples/` (Rust),
`../gotest/` (go-ethereum).
