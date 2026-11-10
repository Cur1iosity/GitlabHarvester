# glh/workers.py
"""
Small thread pool for API-bound work.

Design:

- Tasks come from a lazy iterator and are handed to daemon worker threads
  through a shared queue, so a free thread always takes the next task (load
  balances itself; projects differ in search time by orders of magnitude).
- At most ``window`` tasks are in flight (submitted but not yet consumed by
  the caller), so memory stays bounded however long the task iterator is.
- Results are consumed in the calling (main) thread. Workers never touch
  files, counters or the progress line.
- ``workers == 1`` runs everything inline in the calling thread: no threads,
  exactly the sequential behavior.
- Worker threads are daemons: Ctrl+C in the main thread does not wait for
  requests that are still in flight.
"""

from __future__ import annotations

import queue
import threading
from dataclasses import dataclass
from typing import Any, Callable, Generic, Iterable, Iterator, TypeVar

T = TypeVar("T")
R = TypeVar("R")

_POLL = 0.2  # seconds; keeps queue waits interruptible by Ctrl+C on Windows


@dataclass(slots=True)
class Done(Generic[T]):
    """Outcome of one task: the input item and its result or exception."""

    item: T
    result: Any = None
    error: BaseException | None = None

    def unwrap(self) -> Any:
        """Return the result or re-raise the task's exception."""
        if self.error is not None:
            raise self.error
        return self.result


class _Pool:
    """Feeder thread + daemon workers + bounded window; results in completion order."""

    def __init__(
            self,
            fn: Callable[[Any], Any],
            items: Iterable[Any],
            *,
            workers: int,
            window: int,
            initializer: Callable[[], None] | None,
    ) -> None:
        self._fn = fn
        self._items = iter(items)
        self._window = threading.BoundedSemaphore(window)
        self._tasks: queue.Queue[tuple[int, Any] | None] = queue.Queue()
        self._results: queue.Queue[tuple[int, Done[Any]] | tuple[None, BaseException]] = queue.Queue()
        self._stop = threading.Event()
        self._submitted = 0
        self._feeding_done = threading.Event()
        self._workers = workers
        self._initializer = initializer

    # ------------------------------------------------------------------ threads

    def _feed(self) -> None:
        try:
            for item in self._items:
                while not self._window.acquire(timeout=_POLL):
                    if self._stop.is_set():
                        return
                if self._stop.is_set():
                    return
                self._tasks.put((self._submitted, item))
                self._submitted += 1
        except BaseException as e:  # the task iterator itself failed
            self._results.put((None, e))
        finally:
            self._feeding_done.set()
            for _ in range(self._workers):
                self._tasks.put(None)

    def _work(self) -> None:
        if self._initializer is not None:
            try:
                self._initializer()
            except BaseException as e:
                self._results.put((None, e))
                return
        while not self._stop.is_set():
            task = self._tasks.get()
            if task is None:
                return
            seq, item = task
            try:
                done = Done(item, result=self._fn(item))
            except BaseException as e:  # reported to the caller, never swallowed
                done = Done(item, error=e)
            self._results.put((seq, done))

    # ----------------------------------------------------------------- consumer

    def results(self) -> Iterator[tuple[int, Done[Any]]]:
        threads = [threading.Thread(target=self._feed, name="glh-feeder", daemon=True)]
        threads += [threading.Thread(target=self._work, name=f"glh-worker-{i + 1}", daemon=True)
                    for i in range(self._workers)]
        for t in threads:
            t.start()

        received = 0
        try:
            while not (self._feeding_done.is_set() and received >= self._submitted):
                try:
                    seq, done = self._results.get(timeout=_POLL)
                except queue.Empty:
                    continue
                if seq is None:  # feeder/initializer failure
                    raise done  # type: ignore[misc]
                received += 1
                yield seq, done
        finally:
            self._stop.set()

    def release(self) -> None:
        """Free one window slot (the caller has finished with one result)."""
        self._window.release()


def imap_unordered(
        fn: Callable[[T], R],
        items: Iterable[T],
        *,
        workers: int = 1,
        window: int | None = None,
        initializer: Callable[[], None] | None = None,
) -> Iterator[Done[T]]:
    """
    Run ``fn`` over ``items`` and yield outcomes as tasks finish.

    Exceptions raised by ``fn`` are returned in ``Done.error`` (call
    ``Done.unwrap()``), so the caller decides whether to abort.

    Args:
        fn: Task function, called in a worker thread (or inline if workers == 1).
        items: Lazy iterable of task inputs.
        workers: Number of worker threads; 1 = run inline, in order.
        window: Max tasks in flight (default: 2 x workers).
        initializer: Called once in every worker thread before its first task.
    """
    if workers <= 1:
        for item in items:
            try:
                yield Done(item, result=fn(item))
            except Exception as e:  # noqa: BLE001 - same contract as the threaded path
                yield Done(item, error=e)
        return

    pool = _Pool(fn, items, workers=workers, window=window or 2 * workers, initializer=initializer)
    for _, done in pool.results():
        try:
            yield done
        finally:
            pool.release()


def imap_ordered(
        fn: Callable[[T], R],
        items: Iterable[T],
        *,
        workers: int = 1,
        window: int | None = None,
        initializer: Callable[[], None] | None = None,
) -> Iterator[Done[T]]:
    """
    Like :func:`imap_unordered`, but yield outcomes in input order.

    Later tasks keep running while an earlier one is slow, up to ``window``
    tasks ahead. Stopping the iteration early (``break``) stops submitting
    new tasks; results of tasks still in flight are discarded.
    """
    if workers <= 1:
        yield from imap_unordered(fn, items, workers=1)
        return

    pool = _Pool(fn, items, workers=workers, window=window or 2 * workers, initializer=initializer)
    pending: dict[int, Done[Any]] = {}
    next_seq = 0
    for seq, done in pool.results():
        pending[seq] = done
        while next_seq in pending:
            ready = pending.pop(next_seq)
            next_seq += 1
            try:
                yield ready
            finally:
                pool.release()
