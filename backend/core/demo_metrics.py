from __future__ import annotations

import time
from collections import defaultdict, deque
from contextlib import contextmanager
from threading import Lock
from typing import Any, Iterator


_lock = Lock()
_counters: dict[str, int] = defaultdict(int)
_latencies_ms: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=256))


def inc(name: str, value: int = 1) -> None:
    with _lock:
        _counters[name] += int(value)


def observe_ms(name: str, ms: float) -> None:
    with _lock:
        _latencies_ms[name].append(float(ms))


@contextmanager
def timer(name: str) -> Iterator[None]:
    start = time.perf_counter()
    try:
        yield
    finally:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        observe_ms(name, elapsed_ms)


def _percentile(values: list[float], p: float) -> float | None:
    if not values:
        return None
    values = sorted(values)
    k = int(round((len(values) - 1) * p))
    k = max(0, min(len(values) - 1, k))
    return values[k]


def snapshot() -> dict[str, Any]:
    with _lock:
        counters = dict(_counters)
        lat = {k: list(v) for k, v in _latencies_ms.items()}

    latency_summary: dict[str, Any] = {}
    for name, vals in lat.items():
        latency_summary[name] = {
            "count": len(vals),
            "p50_ms": _percentile(vals, 0.50),
            "p95_ms": _percentile(vals, 0.95),
            "max_ms": max(vals) if vals else None,
        }

    return {"counters": counters, "latency": latency_summary}


