"""Tests for industrialxpl.core.pool SmartPool and helpers."""


import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from industrialxpl.core.pool import PoolStrategy, SmartPool, cpu_count


def test_cpu_count_positive():
    assert cpu_count() >= 1


def test_pool_strategy_values():
    assert PoolStrategy.THREADS.value == "threads"
    assert PoolStrategy.PROCESSES.value == "processes"
    assert PoolStrategy.AUTO.value == "auto"


def test_smartpool_defaults():
    pool = SmartPool()
    assert pool.max_workers >= 1
    assert pool.strategy in ("threads", "processes")


def test_smartpool_threads_strategy():
    pool = SmartPool(max_workers=4, strategy=PoolStrategy.THREADS)
    assert pool.strategy == "threads"
    assert pool.max_workers == 4


def test_smartpool_submit():
    pool = SmartPool(max_workers=2, strategy=PoolStrategy.THREADS)
    future = pool.submit(lambda x: x * 2, 21)
    assert future.result(timeout=5) == 42


def test_smartpool_map_unordered():
    pool = SmartPool(max_workers=2, strategy=PoolStrategy.THREADS)
    results = pool.map_unordered(lambda x: x ** 2, [1, 2, 3, 4])
    values = dict(results)
    assert values[2] == 4
    assert values[4] == 16


def test_smartpool_map_with_error():
    errors = []

    def fail_on_three(x):
        if x == 3:
            raise ValueError("bad")
        return x

    pool = SmartPool(max_workers=2, strategy=PoolStrategy.THREADS)
    results = pool.map_unordered(
        fail_on_three, [1, 2, 3, 4],
        on_error=lambda item, exc: errors.append(item),
    )
    assert len(results) == 3
    assert 3 in errors


def test_smartpool_auto_threads():
    pool = SmartPool(max_workers=2, strategy=PoolStrategy.AUTO)
    assert pool.strategy == "threads"


def test_smartpool_auto_processes():
    cpus = cpu_count()
    pool = SmartPool(max_workers=cpus * 3, strategy=PoolStrategy.AUTO)
    assert pool.strategy == "processes"
