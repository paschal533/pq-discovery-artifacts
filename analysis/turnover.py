"""Open item A — is a first-sight cache miss a node new to the NETWORK, or new to ME?

VERIFICATION.md R9 ruled `seq` churn out as the explanation for the ~15 pp gap between the
measured 85.0% hit rate and 100%, leaving first-sight misses as the cause. But "first sight"
is two different things added together:

  1. a node that already existed and this crawler had not reached yet  -> decays with coverage
  2. a node genuinely new to the network                               -> does not decay

Only the second sets a floor on the hit rate. §7c recorded that separating them needed
repeated crawls tracking the node set. It does not: `seq` already carries the answer.

Most Ethereum nodes seed `seq` once from the wall clock in MILLISECONDS and then increment
by one per record update (R9 §7a: of 1,461 bumps over 23.3 h, 74% were +1 or +2 and *none*
re-seeded from the clock). Updates are rare (~1 %/h), so the increment is negligible against
a ~1.79e12 nominal value and

    seq / 1000  ~=  the unix second at which this record was created.

Two independent checks that this reading is right, both printed below: no record may be
dated in the future, and the newest should be dated moments before the crawl ended.

Usage:
    python turnover.py data/crawl-eth.csv data/crawl-eth-v2.csv
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

MS_LO, MS_HI = 10**12, 2 * 10**12   # plausible ms-since-epoch: 2001-09 .. 2033-05
SEC_LO, SEC_HI = 10**9, 10**12      # a second-style timestamp, if any node uses one
DAY_MS = 86_400_000


def load(path: Path) -> tuple[dict[str, int], int, int]:
    best: dict[str, int] = {}
    lo = hi = None
    skipped = 0
    with path.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if not row.get("seq") or not row.get("node_id"):
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
    return best, lo, hi


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    a, _, a_hi = load(Path(sys.argv[1]))
    b, _, b_hi = load(Path(sys.argv[2]))
    if a_hi > b_hi:
        a, b, a_hi, b_hi = b, a, b_hi, a_hi

    # --- validate the reading of seq before relying on it ---
    ms = {n: s for n, s in b.items() if MS_LO <= s <= MS_HI}
    sec = sum(1 for s in b.values() if SEC_LO <= s < MS_LO)
    future = sum(1 for s in ms.values() if s > b_hi)
    newest_lag_s = (b_hi - max(ms.values())) / 1000 if ms else float("nan")
    print("validating `seq` as a millisecond record-creation timestamp")
    print(f"  ms-style seq              {len(ms):,} of {len(b):,} ({100*len(ms)/len(b):.1f}%)")
    print(f"  second-style seq          {sec:,}  (would need separate handling; expected 0)")
    print(f"  dated in the FUTURE       {future:,}  (must be 0)")
    print(f"  newest record predates crawl end by {newest_lag_s:,.0f} s  (small = the clocks agree)")
    if future or sec:
        print("  !! validation failed - do not use these results")
        return

    gap_ms = b_hi - a_hi
    first_sight = b.keys() - a.keys()
    datable = [n for n in first_sight if n in ms]

    print(f"\nlater crawl                 {len(b):,} nodes")
    print(f"  seen in the earlier crawl {len(b.keys() & a.keys()):,}")
    print(f"  FIRST SIGHT               {len(first_sight):,}")
    print(f"  of which datable          {len(datable):,} ({100*len(datable)/len(first_sight):.1f}%)")
    print(f"gap between crawl ends      {gap_ms/3.6e6:.1f} h")

    ages = [b_hi - b[n] for n in datable]
    rows = [
        ("created since the earlier crawl", lambda x: x < gap_ms),
        ("1-7 days old", lambda x: gap_ms <= x < 7 * DAY_MS),
        ("7-30 days old", lambda x: 7 * DAY_MS <= x < 30 * DAY_MS),
        ("30-180 days old", lambda x: 30 * DAY_MS <= x < 180 * DAY_MS),
        ("over 180 days old", lambda x: x >= 180 * DAY_MS),
    ]
    print(f"\n{'record age of a first-sight node':<36} {'n':>8} {'share':>8}")
    print("-" * 54)
    for label, pred in rows:
        c = sum(1 for x in ages if pred(x))
        print(f"{label:<36} {c:>8,} {100*c/len(ages):>7.1f}%")

    new = sum(1 for x in ages if x < gap_ms)
    print(f"\n{100*new/len(ages):.1f}% of first-sight nodes are genuinely NEW to the network.")
    print(f"{100*(1-new/len(ages)):.1f}% already existed - the crawler simply had not reached them.")

    # --- the bias that could undermine this ---
    # Only ms-style nodes are datable. If counter-style nodes were systematically newer,
    # excluding them would understate turnover. Compare cohort mix in the two populations.
    stable = b.keys() & a.keys()
    mix_stable = sum(1 for n in stable if n in ms) / len(stable)
    mix_first = len(datable) / len(first_sight)
    print(f"\ncohort mix check (ms-style share):")
    print(f"  among nodes seen in both crawls  {100*mix_stable:.1f}%")
    print(f"  among first-sight nodes          {100*mix_first:.1f}%")
    direction = ("OVERstates" if mix_first > mix_stable else "UNDERstates")
    print(f"  -> ms-style nodes are {'over' if mix_first > mix_stable else 'under'}-represented "
          f"among first-sight nodes,\n     so counter-style nodes are comparatively "
          f"{'more' if mix_first > mix_stable else 'less'} stable and the {new/len(ages)*100:.1f}% "
          f"figure {direction} turnover.")


if __name__ == "__main__":
    main()
