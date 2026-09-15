#!/usr/bin/env python3
"""Measure the real byte composition of Ethereum Node Records.

Decodes `enr:` strings and reports, field by field, how the 300-byte budget
(EIP-778) is actually spent, separating the cryptographic fields (signature,
public key) from everything else. The residual is the "non-crypto floor", which
is what a post-quantum identity scheme would have to fit around.

Usage:  python measure_enr.py <file-with-enr-strings> [label]
"""

from __future__ import annotations

import base64
import re
import sys
from collections import Counter
from pathlib import Path

# Field names whose value is cryptographic material rather than metadata.
# Anything not listed here counts toward the non-crypto floor.
CRYPTO_KEYS = {"secp256k1", "id"}


def rlp_decode(b: bytes, pos: int = 0):
    """Minimal RLP decoder. Returns (value, next_pos) where value is bytes or list."""
    if pos >= len(b):
        raise ValueError("truncated")
    p = b[pos]
    if p < 0x80:                                    # single byte
        return b[pos:pos + 1], pos + 1
    if p < 0xB8:                                    # short string
        n = p - 0x80
        return b[pos + 1:pos + 1 + n], pos + 1 + n
    if p < 0xC0:                                    # long string
        ln = p - 0xB7
        n = int.from_bytes(b[pos + 1:pos + 1 + ln], "big")
        s = pos + 1 + ln
        return b[s:s + n], s + n
    if p < 0xF8:                                    # short list
        n = p - 0xC0
        end, out, q = pos + 1 + n, [], pos + 1
        while q < end:
            v, q = rlp_decode(b, q)
            out.append(v)
        return out, end
    ln = p - 0xF7                                   # long list
    n = int.from_bytes(b[pos + 1:pos + 1 + ln], "big")
    s = pos + 1 + ln
    end, out, q = s + n, [], s
    while q < end:
        v, q = rlp_decode(b, q)
        out.append(v)
    return out, end


def rlp_len(item: bytes) -> int:
    """Encoded length of a byte string, including its RLP prefix."""
    n = len(item)
    if n == 1 and item[0] < 0x80:
        return 1
    if n < 56:
        return 1 + n
    return 1 + (n.bit_length() + 7) // 8 + n


def decode_enr(s: str) -> bytes:
    s = s.strip().removeprefix("enr:")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def analyse(raw: bytes) -> dict:
    items, _ = rlp_decode(raw)
    sig, seq, kvs = items[0], items[1], items[2:]

    # Outer list header: total encoded size minus the payload it wraps.
    payload = sum(rlp_len(x) for x in items)
    header = len(raw) - payload

    sig_bytes = rlp_len(sig)
    seq_bytes = rlp_len(seq)

    fields, crypto, noncrypto = {}, 0, 0
    for i in range(0, len(kvs) - 1, 2):
        k, v = kvs[i], kvs[i + 1]
        name = k.decode("utf-8", "replace")
        cost = rlp_len(k) + rlp_len(v)
        fields[name] = cost
        if name in CRYPTO_KEYS and name != "id":
            crypto += cost
        else:
            noncrypto += cost

    return {
        "total": len(raw),
        "header": header,
        "sig": sig_bytes,
        "seq": seq_bytes,
        "key_pair": crypto,          # the secp256k1 pair
        "other_fields": noncrypto,   # id, ip, tcp, udp, eth2, attnets, ...
        "noncrypto_floor": header + seq_bytes + noncrypto,
        "crypto_spend": sig_bytes + crypto,
        "fields": fields,
    }


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    path = Path(sys.argv[1])
    label = sys.argv[2] if len(sys.argv) > 2 else path.stem

    enrs = re.findall(r"enr:[A-Za-z0-9_\-]+", path.read_text(encoding="utf-8"))
    if not enrs:
        print(f"no enr: strings found in {path}")
        return 1

    rows, seen = [], Counter()
    for e in enrs:
        try:
            r = analyse(decode_enr(e))
        except Exception as exc:                    # malformed record, skip loudly
            print(f"  ! skipped one record: {exc}")
            continue
        rows.append(r)
        seen.update(r["fields"].keys())

    n = len(rows)
    avg = lambda k: sum(r[k] for r in rows) / n
    mx = lambda k: max(r[k] for r in rows)
    mn = lambda k: min(r[k] for r in rows)

    print(f"\n=== {label}, {n} records ===\n")
    print(f"{'quantity':24s} {'min':>6s} {'mean':>7s} {'max':>6s}")
    print("-" * 46)
    for key, name in [
        ("total", "total record size"),
        ("sig", "signature (+framing)"),
        ("key_pair", "secp256k1 key pair"),
        ("crypto_spend", "CRYPTO SPEND"),
        ("noncrypto_floor", "NON-CRYPTO FLOOR"),
    ]:
        print(f"{name:24s} {mn(key):6d} {avg(key):7.1f} {mx(key):6d}")

    print(f"\nheadroom to 300 B:       {300 - mx('total'):6d} (worst case)")
    print(f"crypto budget available: {300 - mx('noncrypto_floor'):6d} (worst case)")
    print(f"                         {300 - int(avg('noncrypto_floor')):6d} (mean)")

    print(f"\nfields seen across {n} records:")
    for name, count in seen.most_common():
        costs = [r["fields"][name] for r in rows if name in r["fields"]]
        print(f"  {name:14s} in {count:2d}/{n}  cost {min(costs)}-{max(costs)} B")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
