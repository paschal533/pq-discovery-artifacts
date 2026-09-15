#!/usr/bin/env python3
"""RQ3: how much of discovery's verification work is avoidable?

Replays a crawl log (produced by the hook in prototype/discv5/src/crawl_log.rs)
through a sequence-number cache and reports, under three accounting policies, what
fraction of verifications a node could have skipped.

The log records every ENR as it arrived in a NODES response, *before* discv5
filtered or deduplicated it, because the quantity of interest is precisely how
often the same record comes back.

Policies
--------
strict      hit only when seq is exactly what we already verified.
            Any change re-verifies. The conservative number.
monotonic   hit when seq <= cached seq, i.e. "nothing newer than what I hold".
            Higher rate, but accepting seq < cached means acting on an endpoint
            that has since been superseded.
identity    hit whenever the node id has been seen, ignoring seq entirely.
            Reported as the upper bound and as the unsafe baseline: an attacker
            who controls a known node id can change ip/ports freely under it.

Usage:  python cache_model.py data/crawl-eth.csv [--capacity N]
"""

from __future__ import annotations

import argparse
import csv
import statistics
from collections import Counter, OrderedDict, defaultdict
from dataclasses import dataclass, field

# A seq this large is a millisecond timestamp, not an update counter. A counter
# would need ~10^9 record updates to get here. Clients differ on this and it
# matters: a timestamp-derived seq changes whenever the node restarts.
TIMESTAMP_SEQ_FLOOR = 1_000_000_000


@dataclass
class Observation:
    ts_ms: int
    query_id: str
    source: str
    node_id: str
    seq: int
    size: int


@dataclass
class PolicyResult:
    name: str
    hits: int = 0
    misses: int = 0
    # misses broken down, so the strict/monotonic gap is explainable
    cold: int = 0          # never seen this node before
    seq_newer: int = 0     # seen it, but the record advanced
    seq_older: int = 0     # seen it, and this record is behind what we hold
    evicted: int = 0       # seen it, but the cache had dropped it

    @property
    def total(self) -> int:
        return self.hits + self.misses

    @property
    def hit_rate(self) -> float:
        return self.hits / self.total if self.total else 0.0


class SeqCache:
    """node_id -> highest seq verified. Optionally LRU-bounded.

    Unbounded is the upper bound on savings; a real client cannot cache without
    limit, so --capacity shows how quickly that bound erodes.
    """

    def __init__(self, capacity: int | None = None) -> None:
        self.capacity = capacity
        self._d: OrderedDict[str, int] = OrderedDict()
        self.evictions = 0

    def get(self, node_id: str) -> int | None:
        if node_id not in self._d:
            return None
        self._d.move_to_end(node_id)
        return self._d[node_id]

    def put(self, node_id: str, seq: int) -> None:
        self._d[node_id] = seq
        self._d.move_to_end(node_id)
        if self.capacity is not None and len(self._d) > self.capacity:
            self._d.popitem(last=False)
            self.evictions += 1


def load(path: str) -> list[Observation]:
    out: list[Observation] = []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            try:
                out.append(
                    Observation(
                        ts_ms=int(row["ts_ms"]),
                        query_id=row["query_id"],
                        source=row["source"],
                        node_id=row["node_id"],
                        seq=int(row["seq"]),
                        size=int(row["size"]),
                    )
                )
            except (KeyError, ValueError, TypeError):
                # a torn final line is normal when reading a log still being written
                continue
    out.sort(key=lambda o: o.ts_ms)
    return out


def replay(obs: list[Observation], policy: str, capacity: int | None,
           warm_from: int = 0) -> PolicyResult:
    """Replay the log. `warm_from` skips accounting for the first N observations
    while still populating the cache, which approximates a node that has already
    been running: a short crawl is dominated by cold misses that a long-lived node
    would have paid once, long ago."""
    res = PolicyResult(name=policy)
    cache = SeqCache(capacity)
    ever_seen: set[str] = set()

    for idx, o in enumerate(obs):
        counting = idx >= warm_from
        cached = cache.get(o.node_id)

        if cached is None:
            if counting:
                res.misses += 1
                if o.node_id in ever_seen:
                    res.evicted += 1
                else:
                    res.cold += 1
            cache.put(o.node_id, o.seq)
            ever_seen.add(o.node_id)
            continue

        if policy == "identity":
            hit = True
        elif policy == "monotonic":
            hit = o.seq <= cached
        else:  # strict
            hit = o.seq == cached

        if hit:
            if counting:
                res.hits += 1
            # keep the cache warm; under monotonic an older seq must not overwrite
            if o.seq > cached:
                cache.put(o.node_id, o.seq)
            else:
                cache.get(o.node_id)
        else:
            if counting:
                res.misses += 1
                if o.seq > cached:
                    res.seq_newer += 1
                else:
                    res.seq_older += 1
            cache.put(o.node_id, max(o.seq, cached))

    return res


def describe(obs: list[Observation]) -> None:
    nodes = {o.node_id for o in obs}
    queries = {o.query_id for o in obs if o.query_id != "-"}
    sources = {o.source for o in obs}

    per_query: dict[str, int] = Counter(o.query_id for o in obs if o.query_id != "-")
    responders: dict[str, set[str]] = defaultdict(set)
    for o in obs:
        if o.query_id != "-":
            responders[o.query_id].add(o.source)

    seqs: dict[str, set[int]] = defaultdict(set)
    for o in obs:
        seqs[o.node_id].add(o.seq)
    churned = sum(1 for v in seqs.values() if len(v) > 1)

    ts_like = {n for n, v in seqs.items() if max(v) >= TIMESTAMP_SEQ_FLOOR}

    sizes = [o.size for o in obs]

    print("=" * 72)
    print("CRAWL")
    print("=" * 72)
    print(f"  observations (raw, with repeats) : {len(obs):>8,}")
    print(f"  distinct nodes                   : {len(nodes):>8,}")
    print(f"  distinct responders              : {len(sources):>8,}")
    print(f"  lookups                          : {len(queries):>8,}")
    if per_query:
        vals = sorted(per_query.values())
        print(f"  records per lookup   median/max  : {statistics.median(vals):>8.0f} / {max(vals):,}")
    if responders:
        rv = sorted(len(v) for v in responders.values())
        print(f"  responders per lookup median/max : {statistics.median(rv):>8.0f} / {max(rv):,}")
    print(f"  repeat factor (obs / distinct)   : {len(obs)/len(nodes):>8.1f}x")
    print()
    print(f"  nodes whose seq changed mid-crawl: {churned:>8,}  ({churned/len(nodes)*100:.1f}%)")
    print(f"  nodes using timestamp-like seq   : {len(ts_like):>8,}  ({len(ts_like)/len(nodes)*100:.1f}%)")
    print()
    print(f"  ENR size  median/max  (cap 300 B): {statistics.median(sizes):>8.0f} / {max(sizes)}")
    over = sum(1 for s in sizes if s > 300)
    print(f"  records over the 300-byte cap    : {over:>8,}")

    # RQ1 cross-check. One record per node, so heavily-repeated nodes do not
    # dominate the distribution.
    by_node = {}
    for o in obs:
        by_node[o.node_id] = o.size
    uniq = sorted(by_node.values())

    def pct(p: float) -> int:
        return uniq[min(len(uniq) - 1, int(p / 100 * len(uniq)))]

    print()
    print("  per-node ENR size distribution, and the headroom a PQ scheme would have")
    print("  if it replaced secp256k1 (97 B: 33 B key + 64 B signature):")
    print(f"    {'pct':<6} {'size':>6} {'free to 300':>12} {'budget if 97 B reclaimed':>26}")
    for p in (50, 75, 90, 95, 99, 100):
        s = max(uniq) if p == 100 else pct(p)
        label = "max" if p == 100 else f"p{p}"
        print(f"    {label:<6} {s:>6} {300 - s:>12} {300 - s + 97:>26}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--capacity", type=int, default=None,
                    help="LRU cache bound in entries; omit for unbounded")
    args = ap.parse_args()

    obs = load(args.log)
    if not obs:
        print("no observations")
        return

    describe(obs)

    n_queries = len({o.query_id for o in obs if o.query_id != "-"}) or 1

    print()
    print("=" * 72)
    cap = "unbounded" if args.capacity is None else f"LRU {args.capacity:,}"
    print(f"VERIFICATIONS AVOIDED BY SEQUENCE-NUMBER CACHING  (cache: {cap})")
    print("=" * 72)
    print(f"  {'policy':<11} {'hit rate':>9} {'verifies/lookup':>16} {'cold':>8} {'newer':>8} {'older':>8}")
    print(f"  {'-'*11} {'-'*9} {'-'*16} {'-'*8} {'-'*8} {'-'*8}")

    baseline = len(obs) / n_queries
    for policy in ("strict", "monotonic", "identity"):
        r = replay(obs, policy, args.capacity)
        per_lookup = r.misses / n_queries
        print(f"  {policy:<11} {r.hit_rate*100:>8.1f}% {per_lookup:>16.1f} "
              f"{r.cold:>8,} {r.seq_newer:>8,} {r.seq_older:>8,}")

    print(f"  {'none':<11} {0.0:>8.1f}% {baseline:>16.1f}")

    # Second half only. The cache is already populated by the first half, so this
    # approximates a node that has been running rather than one just started.
    half = len(obs) // 2
    warm_queries = len({o.query_id for o in obs[half:] if o.query_id != "-"}) or 1
    print()
    print(f"  warm steady state (second half of the crawl, cache pre-populated):")
    for policy in ("strict", "monotonic", "identity"):
        r = replay(obs, policy, args.capacity, warm_from=half)
        print(f"  {policy:<11} {r.hit_rate*100:>8.1f}% {r.misses/warm_queries:>16.1f} "
              f"{r.cold:>8,} {r.seq_newer:>8,} {r.seq_older:>8,}")
    print()
    print("  cold  = first sight of this node   newer = record advanced   older = record behind cache")
    print("  'identity' is the unsafe upper bound, not a proposal: it ignores seq, so an")
    print("  attacker holding a known node id can change ip/ports without re-verification.")


if __name__ == "__main__":
    main()
