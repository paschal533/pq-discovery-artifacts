# PQ-Discovery — artifacts

Measurement data, analysis code and test harnesses for a study of post-quantum identity on
discv5-based peer discovery.

Three networks are measured: **Ethereum**'s consensus-layer discv5 (55,095 nodes), **Waku**
(n=56, operated by Logos), and **Codex** (n=8), which runs a discv5-derived DHT using libp2p
Signed Peer Records instead of EIP-778 records. Ethereum and Waku carry the quantitative
results; Codex is used only as an existence proof about the record container.

The accompanying paper is in preparation. This repository is published independently of it so
that every figure can be re-derived from the data rather than taken on trust.

## The question

An ENR is capped at 300 bytes, and the signature sits *inside* the record it signs. The work
measures what that leaves for cryptography across a real network, what verification actually
costs per lookup, and whether a new identity scheme could be deployed incrementally at all.

## Contents

| path | what it is |
|---|---|
| `data/crawl-eth-v2.csv` | the main crawl — 600 random-target FINDNODE lookups, 68 minutes, 378,337 record observations across 55,095 distinct nodes |
| `data/crawl-eth.csv`, `crawl-eth-long.csv`, `crawl-eth-pilot.csv` | earlier and longer-interval Ethereum crawls, used for churn and turnover measurement |
| `data/crawl-waku*.csv` | Waku crawls (n=56, ~60,500 observations) — a small, homogeneous, near-cap network used as a regime contrast against Ethereum |
| `data/liboqs-speed-sig*.txt` | signature verification benchmarks, both build targets |
| `data/qruov-sizes.tsv` | QR-UOV parameter sizes read from the reference implementation |
| `analysis/*.py` | every script that turns the CSVs into the paper's figures |
| `harnesses/gotest/` | go-ethereum ENR decode behaviour, run rather than read |
| `harnesses/nimtest/` | nim-eth ENR decode behaviour |
| `discv5-instrumentation.patch` | the read-only logging hook added to `sigp/discv5`, plus the Rust harnesses |

### CSV schema

```
ts_ms,query_id,source,node_id,seq,size
```

`source` and `node_id` are 32-byte node ids in hex — the hash of a public key, not a network
locator. `seq` is the record's sequence number, `size` its encoded length in bytes.

## What is not here, and why

**Raw ENRs and crawler logs are deliberately withheld.** A full ENR contains the node's IP
address, and while an ENR is a record a node signs and broadcasts precisely so strangers will
read it, an IP address is personal data regardless of how willingly it was published.

The CSVs published here were audited for this rather than assumed safe: they contain no IPv4 or
IPv6 addresses in any form. Note that a plaintext search is *not* sufficient to establish that
for ENR files — records are base64-encoded, so addresses inside them are invisible to a naive
grep. That is why the withheld files are withheld by category, not by scan result.

Where a result depends on record contents — field decomposition, size distributions — the
published artifact is the derived measurement rather than the underlying records. If you need
the raw records for review, open an issue: they can be republished with `ip`, `ip6` and
`multiaddrs` removed, which preserves everything the analyses use, at the cost of the records no
longer carrying verifiable signatures.

**Codex source records are also withheld**, for the same reason. Codex publishes libp2p Signed
Peer Records (`spr:`) rather than ENRs, and these likewise embed addresses inside a base64
encoding — they scan clean as plaintext and are not. The Codex figures in the paper are record
*sizes* (189–190 bytes), which the derived measurements carry.

No attempt is made anywhere in this work to associate a node with a person or an organisation.

**Conflict of interest.** Waku is operated by Logos, the author's employer. The Waku measurements
here are of a production fleet operated by that employer.

## Reproducing

The upstream trees are not vendored here. Pin them as follows, which is what every figure was
produced against:

| | pin |
|---|---|
| `sigp/discv5` | `5129edac42192802f3c1ccb8f8c85cd698eb9ee9` (v0.11.0 line) |
| `enr` crate | 0.13.0 |
| `open-quantum-safe/liboqs` | `adbeba1` (2026-09-11) |
| `status-im/nim-eth` | `cde1950` (2026-09-02) |
| `ethereum/go-ethereum` | v1.17.5 |

The liboqs commit **includes the Round 3 UOV and MAYO updates merged upstream on 2026-09-09**,
while the library's version string still reads `0.16.0` and that *release* predates them. Pin the
commit, not the version string — the difference is not detectable from the version alone.

```bash
# crawler
git clone https://github.com/sigp/discv5 && cd discv5
git checkout 5129edac42192802f3c1ccb8f8c85cd698eb9ee9
git apply ../discv5-instrumentation.patch
```

These scripts run directly against the published CSVs:

| script | what it produces |
|---|---|
| `cache_model.py` | cache hit rate, and its exact decomposition into first-sight and churn |
| `decompose_hits.py` | per-crawl-length hit rate table |
| `seq_churn.py` | record republication rate between crawls |
| `turnover.py` | new-identity rate, and the age distribution of first-sight nodes |

Two scripts need raw records, which are withheld for the reasons above:

| script | input | how to obtain it |
|---|---|---|
| `decompose_multiaddrs.py` | `waku-enrs.txt` | regenerate with `python analysis/fetch_waku_enrs.py`, which collects them live |
| `reclaim.py` | `waku-records.txt` | produced by a Waku crawl; open an issue for a redacted copy |

`measure_enr.py` takes a record file as an argument and works on any ENR source.

On Windows, `CGO_ENABLED=0` is required for the Go harness — geth's default secp256k1 is cgo
bound to a vendored libsecp256k1 whose headers are not in the module zip.

## Caveats worth reading before citing a number

- **One vantage point.** Every figure is what a single host in a single location saw. A node it
  never reached is indistinguishable in this data from one that does not exist.
- **The crawler is not a typical node.** It issues random-target lookups continuously to maximise
  coverage, so per-lookup discovery rates here are upper bounds.
- **The hit rate had not converged** when the main crawl ended — 71.45% at 60 lookups, 85.02% at
  600. It is a lower bound, and the crawl length must be quoted beside it.
- **Waku is n=56 and Codex n=8.** Too small to support percentages as results; used as contrast.
- **Consensus layer only.** Seeded from CL bootnodes; the execution layer is a separate network
  whose records carry different fields.
- **Timings are from one machine.** Absolute times are indicative; the ratios are the claim.

## Licence

Data and documentation: CC BY 4.0. Code: MIT.
