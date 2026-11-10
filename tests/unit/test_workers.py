"""Thread pool used for parallel API work (glh.workers)."""

from __future__ import annotations

import itertools
import threading
import time

import pytest

from glh.workers import imap_ordered, imap_unordered


class Gauge:
    """Track how many calls run at the same time."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.now = 0
        self.peak = 0
        self.calls = 0
        self.threads: set[str] = set()

    def __call__(self, delay: float):
        def fn(x):
            with self.lock:
                self.now += 1
                self.calls += 1
                self.peak = max(self.peak, self.now)
                self.threads.add(threading.current_thread().name)
            try:
                time.sleep(delay(x) if callable(delay) else delay)
                return x * 10
            finally:
                with self.lock:
                    self.now -= 1
        return fn


def test_single_worker_runs_inline_and_in_order():
    seen = []

    def fn(x):
        seen.append(threading.current_thread() is threading.main_thread())
        if x == 2:
            raise ValueError("boom")
        return x

    out = list(imap_unordered(fn, range(4), workers=1))
    assert [d.item for d in out] == [0, 1, 2, 3]
    assert all(seen)
    assert isinstance(out[2].error, ValueError) and out[3].unwrap() == 3
    with pytest.raises(ValueError):
        out[2].unwrap()


def test_unordered_runs_in_parallel_within_the_worker_limit():
    gauge = Gauge()
    out = list(imap_unordered(gauge(0.05), range(12), workers=4))
    assert sorted(d.unwrap() for d in out) == [x * 10 for x in range(12)]
    assert 2 <= gauge.peak <= 4
    assert len(gauge.threads) > 1 and threading.current_thread().name not in gauge.threads


def test_ordered_keeps_input_order_when_tasks_finish_out_of_order():
    gauge = Gauge()
    out = list(imap_ordered(gauge(lambda x: 0.08 if x % 3 == 0 else 0.0), range(10), workers=4))
    assert [d.item for d in out] == list(range(10))
    assert [d.unwrap() for d in out] == [x * 10 for x in range(10)]


def test_window_bounds_work_in_flight():
    """A slow consumer never has more than `window` tasks started but not consumed."""
    gauge = Gauge()
    consumed = 0
    for _ in imap_unordered(gauge(0.0), range(50), workers=4, window=6):
        consumed += 1
        time.sleep(0.01)
        assert gauge.calls - consumed <= 6
    assert consumed == 50


def test_breaking_early_stops_submitting_tasks():
    gauge = Gauge()
    for done in imap_ordered(gauge(0.01), itertools.count(1), workers=3, window=6):
        if done.item == 5:
            break
    time.sleep(0.1)  # let in-flight tasks finish
    assert gauge.calls <= 5 + 6


def test_initializer_runs_once_per_worker_thread():
    names: list[str] = []
    lock = threading.Lock()

    def init():
        with lock:
            names.append(threading.current_thread().name)

    list(imap_unordered(lambda x: x, range(20), workers=3, initializer=init))
    assert len(names) == len(set(names)) == 3


def test_failing_task_iterator_is_reported_to_the_caller():
    def items():
        yield 1
        raise RuntimeError("index file is broken")

    with pytest.raises(RuntimeError, match="index file is broken"):
        list(imap_unordered(lambda x: x, items(), workers=2))


def test_task_errors_do_not_stop_other_tasks():
    def fn(x):
        if x == 3:
            raise KeyError(x)
        return x

    out = list(imap_ordered(fn, range(6), workers=3))
    assert [d.error is not None for d in out] == [False, False, False, True, False, False]
