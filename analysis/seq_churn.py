"""Gap #4: how often does a node bump its `seq`, and what does that cost the cache?

V-04 measures the cache hit rate *within* one crawl, where almost no node has time to
update its record. V-16 shows that rate is a lower bound as lookups increase. V-11 says
the opposite pressure is real but unmeasured: over hours and days, nodes republish, `seq`
rises, and every rise is a forced re-verification.

This measures that second effect from crawls already on disk, by intersecting node sets
between two crawls taken at different wall-clock times and asking how many nodes moved.

Usage:
    python seq_churn.py data/crawl-eth.csv data/crawl-eth-v2.csv
"""

from __future__ import annotations

import csv
import sys
from collections import defaultdict
from pathlib import Path

# V-10's threshold: a seq at or above this is a unix timestamp, not a counter.
TIMESTAMP_SEQ = 10**9


def load(path: Path) -> tuple[dict[str, int], tuple[int, int]]:
    """node_id -> highest seq observed, plus the crawl's (first, last) ts_ms.

    A crawl killed mid-write leaves one truncated final row (crawl-eth-long.csv has
    exactly this, from the run that died when the machine slept). Skipping it silently
    would hide a genuinely truncated file, so the count is reported.
    """
    best: dict[str, int] = {}
    lo = hi = None
    skipped = 0
    with path.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if row.get("seq") is None or row.get("node_id") is None:
                skipped += 1
                continue
            ts = int(row["ts_ms"])
            lo = ts if lo is None else min(lo, ts)
            hi = ts if hi is None else max(hi, ts)
            nid, seq = row["node_id"], int(row["seq"])
            if seq > best.get(nid, -1):
                best[nid] = seq
    if skipped:
        print(f"note: {path.name}: skipped {skipped} incomplete row(s)")
    return best, (lo, hi)


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    a_path, b_path = Path(sys.argv[1]), Path(sys.argv[2])
    a, (a_lo, a_hi) = load(a_path)
    b, (b_lo, b_hi) = load(b_path)

    # Order by wall clock, not by argument order.
    if a_lo > b_lo:
        a, b = b, a
        a_path, b_path = b_path, a_path
        (a_lo, a_hi), (b_lo, b_hi) = (b_lo, b_hi), (a_lo, a_hi)

    gap_h = (b_lo - a_hi) / 3_600_000.0
    span_h = (b_hi - a_lo) / 3_600_000.0
    both = a.keys() & b.keys()

    print(f"earlier : {a_path.name:22s} {len(a):>7,} nodes")
    print(f"later   : {b_path.name:22s} {len(b):>7,} nodes")
    print(f"seen in both                    {len(both):>7,} nodes "
          f"({100*len(both)/min(len(a), len(b)):.1f}% of the smaller crawl)")
    print(f"gap between crawls              {gap_h:>7.1f} h  (end of first -> start of second)")
    print(f"total span                      {span_h:>7.1f} h")

    if not both:
        print("\nno overlap; nothing to say")
        return

    # Split by seq style, because the two behave differently under restart.
    cohorts: dict[str, list[str]] = defaultdict(list)
    for nid in both:
        cohorts["timestamp" if a[nid] >= TIMESTAMP_SEQ else "counter"].append(nid)

    print()
    hdr = f"{'cohort':<12} {'n':>7} {'bumped':>8} {'rate':>7} {'fell':>6} {'median bump':>13}"
    print(hdr)
    print("-" * len(hdr))

    for name in ("timestamp", "counter"):
        ids = cohorts.get(name, [])
        if not ids:
            continue
        deltas = [b[n] - a[n] for n in ids]
        up = [d for d in deltas if d > 0]
        down = sum(1 for d in deltas if d < 0)
        med = sorted(up)[len(up) // 2] if up else 0
        print(f"{name:<12} {len(ids):>7,} {len(up):>8,} "
              f"{100*len(up)/len(ids):>6.1f}% {down:>6,} {med:>13,}")

    all_deltas = [b[n] - a[n] for n in both]
    up_all = sum(1 for d in all_deltas if d > 0)
    print(f"{'ALL':<12} {len(both):>7,} {up_all:>8,} {100*up_all/len(both):>6.1f}%")

    # What it costs: every bump is one forced signature verification per observer.
    rate = up_all / len(both)
    print(f"\nOver {gap_h:.1f} h, {100*rate:.1f}% of re-seen nodes forced a re-verification.")
    if gap_h > 0:
        print(f"Crude linear extrapolation: {100*rate/gap_h:.2f}%/h, "
              f"{min(100.0, 100*rate*24/gap_h):.1f}%/day.")
        print("Linear extrapolation is an UPPER bound on the daily rate: a node that "
              "\nrepublishes twice in the window is counted once here, so the per-hour "
              "\nfigure understates short-horizon churn and overstates long-horizon churn.")

    # A node whose seq never moved costs nothing, however long the horizon.
    static = sum(1 for d in all_deltas if d == 0)
    print(f"\n{static:,} of {len(both):,} ({100*static/len(both):.1f}%) did not move at all.")


if __name__ == "__main__":
    main()
