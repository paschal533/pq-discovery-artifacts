#!/usr/bin/env python3
"""Decompose the `multiaddrs` field of a Waku ENR to find where the bytes go.

§2 of BUDGET.md shows Waku records reach 295 of 300 bytes, with `multiaddrs`
costing 103-127 B of that. This decodes the field to show exactly what is inside,
and estimates how much is recoverable, which decides whether Waku can reach a
post-quantum identity scheme by reclaiming bytes rather than waiting for a
smaller signature.

The ENR `multiaddrs` value is a concatenation of entries, each a 2-byte
big-endian length followed by that many bytes of binary multiaddr.

Usage:  python decompose_multiaddrs.py <file-with-enr-strings>
"""

from __future__ import annotations

import sys

# Hostnames can decode to replacement characters; the Windows console is cp1252
# and would raise on them rather than print.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
from collections import Counter
from pathlib import Path

from measure_enr import decode_enr, rlp_decode, rlp_len

# multiaddr protocol codes -> (name, size in bytes, or -1 for varint-length-prefixed)
PROTOCOLS = {
    4: ("ip4", 4), 6: ("tcp", 2), 41: ("ip6", 16), 53: ("dns", -1),
    54: ("dns4", -1), 55: ("dns6", -1), 56: ("dnsaddr", -1),
    273: ("udp", 2), 421: ("p2p", -1), 477: ("ws", 0), 478: ("wss", 0),
    290: ("quic", 0), 460: ("quic-v1", 0),
}


def uvarint(b: bytes, i: int) -> tuple[int, int]:
    n, shift = 0, 0
    while i < len(b):
        c = b[i]
        n |= (c & 0x7F) << shift
        i += 1
        if not c & 0x80:
            return n, i
        shift += 7
    raise ValueError("truncated varint")


def parse_multiaddr(b: bytes) -> list[tuple[str, str, int]]:
    """Return [(protocol, value, bytes consumed), ...]."""
    out, i = [], 0
    while i < len(b):
        start = i
        code, i = uvarint(b, i)
        name, size = PROTOCOLS.get(code, (f"proto-{code}", 0))
        if size == 0:
            out.append((name, "", i - start))
        elif size > 0:
            val = b[i:i + size]
            if name in ("tcp", "udp"):
                shown = str(int.from_bytes(val, "big"))
            elif name == "ip4":
                shown = ".".join(str(x) for x in val)
            else:
                shown = val.hex()
            i += size
            out.append((name, shown, i - start))
        else:
            ln, i = uvarint(b, i)
            val = b[i:i + ln]
            i += ln
            out.append((name, val.decode("utf-8", "replace"), i - start))
    return out


def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "data/waku-enrs.txt")
    import re
    enrs = re.findall(r"enr:[A-Za-z0-9_\-]+", path.read_text(encoding="utf-8"))

    totals, host_bytes, addr_counts, hosts = [], [], [], Counter()

    for e in enrs:
        items, _ = rlp_decode(decode_enr(e))
        kvs = items[2:]
        ma = None
        for i in range(0, len(kvs) - 1, 2):
            if kvs[i] == b"multiaddrs":
                ma = kvs[i + 1]
        if ma is None:
            continue

        field_cost = rlp_len(b"multiaddrs") + rlp_len(ma)
        totals.append(field_cost)

        print(f"\n--- record: multiaddrs field = {field_cost} B "
              f"(value {len(ma)} B + {field_cost - len(ma)} B framing) ---")

        i, per_record_hosts, n_addrs = 0, 0, 0
        while i + 2 <= len(ma):
            ln = int.from_bytes(ma[i:i + 2], "big")
            i += 2
            entry = ma[i:i + ln]
            i += ln
            if not entry:
                continue
            n_addrs += 1
            parts = parse_multiaddr(entry)
            rendered = "".join(f"/{p}" + (f"/{v}" if v else "") for p, v, _ in parts)
            print(f"   [{ln + 2:3d} B] {rendered}")
            for p, v, cost in parts:
                if p.startswith("dns"):
                    per_record_hosts += cost
                    hosts[v] += 1
        addr_counts.append(n_addrs)
        host_bytes.append(per_record_hosts)

    n = len(totals)
    if not n:
        print("no multiaddrs fields found")
        return 1

    print("\n" + "=" * 66)
    print(f"records with multiaddrs : {n}")
    print(f"field cost              : {min(totals)}-{max(totals)} B "
          f"(mean {sum(totals)/n:.0f})")
    print(f"multiaddrs per record   : {min(addr_counts)}-{max(addr_counts)}")
    print(f"DNS hostname bytes      : {min(host_bytes)}-{max(host_bytes)} B "
          f"(mean {sum(host_bytes)/n:.0f})")
    print(f"  as share of the field : {sum(host_bytes)/sum(totals)*100:.0f}%")
    print(f"  as share of 300 B cap : {sum(host_bytes)/n/300*100:.0f}%")

    print(f"\ndistinct hostnames seen ({len(hosts)}):")
    for h, c in hosts.most_common():
        print(f"  x{c}  {len(h):3d} B  {h}")

    dup = sum(c - 1 for c in hosts.values())
    if dup:
        wasted = sum(len(h) * (c - 1) for h, c in hosts.items())
        print(f"\nrepeated hostnames cost {wasted} B across the sample "
              f"({wasted/n:.0f} B per record), recoverable by encoding each host once")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
