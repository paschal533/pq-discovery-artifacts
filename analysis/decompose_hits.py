"""R10 — split the cache miss rate into its two terms, exactly.

Every distinct node is first-sighted exactly once, so

    misses = distinct nodes + churn misses

is an identity, not a fitted model. This prints both terms. The churn term is taken as the
residual, which is also a check on it: it should grow with elapsed time, and it does.

Usage:
    python decompose_hits.py data/crawl-eth-v2.csv [--cuts 60,120,240,360,480,600]
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path


def rows(path: Path) -> tuple[list[tuple[int, str, int]], int]:
    """(query_id, node_id, seq), plus a count of rows that could not be used.

    Skipped rows are of two kinds and both are reported rather than hidden: a crawl killed
    mid-write leaves one truncated line, and a handful of observations are direct (the node
    talking about itself) and carry no query_id.
    """
    out, skipped = [], 0
    with path.open(newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            if not r.get("seq") or not r.get("node_id"):
                skipped += 1
                continue
            try:
                q = int(r["query_id"])
            except (TypeError, ValueError):
                skipped += 1
                continue
            out.append((q, r["node_id"], int(r["seq"])))
    out.sort(key=lambda x: x[0])
    return out, skipped


def main() -> None:
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)
    path = Path(args[0])
    cuts = None
    if "--cuts" in args:
        cuts = [int(c) for c in args[args.index("--cuts") + 1].split(",")]

    data, skipped = rows(path)
    if skipped:
        print(f"note: skipped {skipped} row(s): incomplete, or direct observations "
              f"with no query_id")
    if cuts is None:
        cuts = [max(q for q, _, _ in data)]

    hdr = (f"{'lookups':>8} {'observations':>13} {'distinct':>9} "
           f"{'1-dist/obs':>11} {'measured':>10} {'churn term':>11}")
    print(hdr)
    print("-" * len(hdr))
    for cut in cuts:
        seen: dict[str, int] = {}
        obs = miss = 0
        for q, n, s in data:
            if q > cut:
                break
            obs += 1
            if n not in seen:                 # first sight
                miss += 1
                seen[n] = s
            elif s > seen[n]:                 # monotonic policy: a newer seq
                miss += 1
                seen[n] = s
        if not obs:
            continue
        model = 1 - len(seen) / obs
        meas = 1 - miss / obs
        print(f"{cut:>8} {obs:>13,} {len(seen):>9,} {100*model:>10.2f}% "
              f"{100*meas:>9.2f}% {100*(model-meas):>10.2f} pp")


if __name__ == "__main__":
    main()
