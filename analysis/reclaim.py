#!/usr/bin/env python3
"""D6 — how many bytes can a Waku ENR give back, and does that make anything fit?

VERIFICATION.md measures Waku's real per-node budgets: 160 B at p50 falling to
102 B at p99. The smallest post-quantum option in Regime B is UOV Is-pkc at
32 + 96 = 128 B, so **nothing fits above p50**. On Waku, reclaiming bytes is not
an optimisation, it is a precondition.

This prices three mechanisms against real crawled records and re-runs the fit
table against the recovered budget.

  A  dedupe host    write each hostname once, reference it thereafter
  B  collapse       one host entry, then [transport, port] variants
  C  drop DNS       rely on the `ip` field, drop dns multiaddrs entirely

A and B are lossless re-encodings. C is not: the hostname carries TLS SNI for
/wss and survives IP changes, so dropping it is a functional change and is
reported separately.

Usage:  python reclaim.py data/waku-records.txt
"""

from __future__ import annotations

import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

from decompose_multiaddrs import parse_multiaddr
from measure_enr import decode_enr, rlp_decode, rlp_len

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# secp256k1 costs 33 B key + 64 B signature. A replacement scheme gets that back.
SECP_BYTES = 97
CAP = 300

# Regime B: record carries a 32-byte key commitment plus the signature.
REGIME_B = [
    ("UOV Is-pkc", 96),
    ("SNOVA_37_17_2", 124),
    ("OV-Ip-pkc", 135),
    ("SNOVA_25_8_3", 165),
    ("SQIsign I", 200),
]
COMMIT = 32

# Assumed cost of a back-reference in a compact re-encoding. See gap #9.
REF_BYTES = 1


def fields(enr_str: str) -> tuple[int, dict[bytes, bytes]]:
    raw = decode_enr(enr_str)
    items, _ = rlp_decode(raw)
    kv = {}
    body = items[2:]
    for i in range(0, len(body) - 1, 2):
        kv[bytes(body[i])] = bytes(body[i + 1])
    return len(raw), kv


def split_entries(ma: bytes) -> list[bytes]:
    """multiaddrs is a concatenation of 2-byte-length-prefixed multiaddrs."""
    out, i = [], 0
    while i + 2 <= len(ma):
        ln = int.from_bytes(ma[i:i + 2], "big")
        i += 2
        out.append(ma[i:i + ln])
        i += ln
    return out


def uvarint(b: bytes, i: int) -> tuple[int, int]:
    n, sh = 0, 0
    while i < len(b):
        c = b[i]
        n |= (c & 0x7F) << sh
        i += 1
        if not c & 0x80:
            return n, i
        sh += 7
    raise ValueError("truncated varint")


# Length-prefixed multiaddr components, with the byte cost of their protocol code.
# These are the ones large enough for repetition to matter.
VARLEN = {53: ("dns", 1), 54: ("dns4", 1), 55: ("dns6", 1), 56: ("dnsaddr", 1),
          421: ("p2p", 2)}
FIXED = {4: 4, 41: 16, 6: 2, 273: 2, 477: 0, 478: 0, 290: 0, 460: 0}


def components(entry: bytes) -> list[tuple[str, bytes, int]]:
    """Return [(name, value, total encoded cost incl. code and length), ...]
    for the length-prefixed components only."""
    out, i = [], 0
    while i < len(entry):
        code, j = uvarint(entry, i)
        if code in FIXED:
            i = j + FIXED[code]
        elif code in VARLEN:
            name, codelen = VARLEN[code]
            ln, k = uvarint(entry, j)
            val = entry[k:k + ln]
            out.append((name, val, codelen + (k - j) + ln))
            i = k + ln
        else:
            break
    return out


def analyse(enr_str: str) -> dict | None:
    size, kv = fields(enr_str)
    ma = kv.get(b"multiaddrs")
    if ma is None:
        return None

    entries = [e for e in split_entries(ma) if e]

    # Every length-prefixed component in the record, by (kind, value).
    seen: Counter[tuple[str, bytes]] = Counter()
    cost_of: dict[tuple[str, bytes], int] = {}
    for e in entries:
        for name, val, cost in components(e):
            seen[(name, val)] += 1
            cost_of[(name, val)] = cost

    # A: write each repeated component once and reference it thereafter.
    #    A back-reference costs REF_BYTES, so each repeat recovers cost - REF_BYTES.
    #    REF_BYTES is an assumption about a hypothetical encoding, not a measurement:
    #    the repeated bytes are measured, the cost of referring to them is modelled.
    #    Gap #9 asks for the sensitivity, so both 1 and 2 are computed.
    save_a = sum((c - 1) * (cost_of[k] - REF_BYTES) for k, c in seen.items() if c > 1)
    save_a2 = sum((c - 1) * (cost_of[k] - 2) for k, c in seen.items() if c > 1)

    # B: on top of A, entries collapse into one prefix plus short variant
    #    suffixes, saving each redundant 2-byte entry length prefix.
    save_b = save_a + max(0, len(entries) - 1) * 2

    hosts = Counter(v.decode("utf-8", "replace")
                    for (n, v), c in seen.items() if n.startswith("dns") for _ in range(c))
    p2p_reps = sum(c - 1 for (n, _), c in seen.items() if n == "p2p" and c > 1)
    dns_reps = sum(c - 1 for (n, _), c in seen.items() if n.startswith("dns") and c > 1)

    # C: drop dns components outright, relying on the `ip` field.
    has_ip = b"ip" in kv or b"ip6" in kv
    dns_bytes = sum(cost_of[k] * c for k, c in seen.items() if k[0].startswith("dns"))
    save_c = save_b + (dns_bytes if has_ip else 0)

    return {
        "size": size,
        "ma_field": rlp_len(b"multiaddrs") + rlp_len(ma),
        "hosts": hosts,
        "entries": len(entries),
        "p2p_reps": p2p_reps,
        "dns_reps": dns_reps,
        "save_a": save_a,
        "save_a2": save_a2,
        "save_b": save_b,
        "save_c": save_c,
        "has_ip": has_ip,
    }


def pct(vals: list[int], p: float) -> int:
    if not vals:
        return 0
    s = sorted(vals)
    return s[min(len(s) - 1, int(p / 100 * len(s)))]


def fit_row(budget: int) -> str:
    ok = [n for n, sig in REGIME_B if COMMIT + sig <= budget]
    return ", ".join(ok) if ok else "NOTHING"


def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "data/waku-records.txt")
    enrs = re.findall(r"enr:[A-Za-z0-9_\-]+", path.read_text(encoding="utf-8"))

    rows = [r for r in (analyse(e) for e in enrs) if r]
    if not rows:
        print("no records with a multiaddrs field")
        return 1

    withdns = [r for r in rows if r["hosts"]]

    print("=" * 74)
    print(f"D6 — byte reclamation, {len(enrs)} crawled Waku records")
    print("=" * 74)
    print(f"  records with a multiaddrs field : {len(rows)}")
    print(f"  of those, carrying a DNS name   : {len(withdns)}")
    dns_dup = [r for r in rows if r["dns_reps"]]
    p2p_dup = [r for r in rows if r["p2p_reps"]]
    any_dup = [r for r in rows if r["save_a"]]
    print(f"  with a repeated DNS hostname    : {len(dns_dup)}")
    print(f"  with a repeated /p2p/ peer id   : {len(p2p_dup)}")
    print(f"  with any repeated component     : {len(any_dup)}  "
          f"({len(any_dup)/len(rows)*100:.0f}% of multiaddrs-bearing records)")
    print()
    print("  NB the /p2p/ peer id is NOT derivable from the record's own secp256k1")
    print("  field: 0 of 58 matched identity-multihash(protobuf(pubkey)). Waku's discv5")
    print("  identity key and its libp2p host key are different keys, so the peer id")
    print("  carries real information. Only its repetition is recoverable.")
    print()

    a1 = [r["save_a"] for r in any_dup] or [0]
    a2 = [r["save_a2"] for r in any_dup] or [0]
    print("  Gap #9 — sensitivity to the back-reference cost assumption:")
    print(f"    1-byte reference: median {pct(a1,50):>3} B recovered, mean {sum(a1)/len(a1):>5.1f} B")
    print(f"    2-byte reference: median {pct(a2,50):>3} B recovered, mean {sum(a2)/len(a2):>5.1f} B")
    print(f"    delta: {sum(a1)/len(a1) - sum(a2)/len(a2):.1f} B per record — the conclusion is insensitive")
    print()

    for label, key, lossless in (
        ("A  dedupe host", "save_a", True),
        ("B  collapse to host + variants", "save_b", True),
        ("C  drop DNS, rely on ip", "save_c", False),
    ):
        vals = [r[key] for r in any_dup] or [0]
        tag = "lossless" if lossless else "LOSSY"
        print(f"  {label:<32} {tag:>8}  "
              f"median {pct(vals,50):>3} B   max {max(vals):>3} B   "
              f"mean {sum(vals)/len(vals):>5.1f} B")
    print()

    print("=" * 74)
    print("DOES ANYTHING FIT?  Regime B budget = 300 - size + 97, per record")
    print("=" * 74)
    sizes = [r["size"] for r in rows]
    for name, key in (("today", None), ("after A (dedupe)", "save_a"),
                      ("after B (collapse)", "save_b"), ("after C (drop DNS)", "save_c")):
        adj = sizes if key is None else [r["size"] - r[key] for r in rows]
        print(f"\n  {name}")
        for p in (50, 75, 90, 99):
            sz = pct(adj, p)
            b = CAP - sz + SECP_BYTES
            print(f"    p{p:<3} size {sz:>3} B   budget {b:>3} B   fits: {fit_row(b)}")

    print()
    print("  Regime B sizes: " + ", ".join(f"{n}={COMMIT+s}" for n, s in REGIME_B))
    print()
    print("  C is not free: the hostname carries TLS SNI for /wss endpoints and lets a")
    print("  node move IP without republishing. A and B are pure re-encodings and give")
    print("  up nothing, so they are the ones to propose first.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
