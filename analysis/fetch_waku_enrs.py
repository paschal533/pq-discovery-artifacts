#!/usr/bin/env python3
"""Walk an EIP-1459 DNS discovery tree and collect the ENRs at its leaves.

Waku publishes its fleet via `enrtree://`, not a static file, so the records have
to be pulled out of DNS. The tree is a Merkle structure: the root TXT names a
subtree hash, each subtree node is a TXT record at <hash>.<domain> holding either
`enrtree-branch:h1,h2,...` or a single `enr:...` leaf.

DNS TXT strings cap at 255 characters, so long records arrive split and must be
concatenated before decoding.

Usage:  python fetch_waku_enrs.py <domain> [max_records]
"""

from __future__ import annotations

import re
import subprocess
import sys


def txt(name: str) -> str:
    """Return a TXT record with its split strings concatenated, or ''."""
    try:
        out = subprocess.run(
            ["nslookup", "-type=TXT", name],
            capture_output=True, text=True, timeout=20,
        ).stdout
    except Exception:
        return ""
    parts = re.findall(r'"([^"]*)"', out)
    return "".join(parts)


def walk(domain: str, node: str, seen: set[str], enrs: list[str], limit: int) -> None:
    if len(enrs) >= limit or node in seen:
        return
    seen.add(node)

    rec = txt(f"{node}.{domain}")
    if not rec:
        return

    if rec.startswith("enrtree-branch:"):
        for child in rec.removeprefix("enrtree-branch:").split(","):
            child = child.strip()
            if child:
                walk(domain, child, seen, enrs, limit)
    elif rec.startswith("enr:"):
        enrs.append(rec)
        print(f"  found ENR #{len(enrs)} ({len(rec)} chars)", file=sys.stderr)


def main() -> int:
    domain = sys.argv[1] if len(sys.argv) > 1 else "prod.wakuv2.nodes.status.im"
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 30

    root = txt(domain)
    if not root.startswith("enrtree-root:"):
        print(f"no enrtree-root at {domain}; got: {root[:80]}", file=sys.stderr)
        return 1

    m = re.search(r"\be=([A-Z2-7]+)", root)
    if not m:
        print("root TXT has no e= subtree hash", file=sys.stderr)
        return 1

    print(f"walking {domain} from subtree {m.group(1)}", file=sys.stderr)
    enrs: list[str] = []
    walk(domain, m.group(1), set(), enrs, limit)

    print("\n".join(enrs))
    print(f"\ncollected {len(enrs)} records", file=sys.stderr)
    return 0 if enrs else 1


if __name__ == "__main__":
    raise SystemExit(main())
