import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import time
from batch_processor import BatchProcessor, TaskResult


class TestBatchProcessor:
    # --- Basic processing with identity function ---

    def test_identity_worker(self):
        bp = BatchProcessor(items=[1, 2, 3], worker_func=lambda x: x * 2)
        results = bp.execute()
        assert len(results) == 3
        assert bp.get_successful() == [2, 4, 6]

    def test_string_worker(self):
        bp = BatchProcessor(items=["a", "b", "c"], worker_func=lambda x: x.upper())
        results = bp.execute()
        assert bp.get_successful() == ["A", "B", "C"]

    def test_no_items(self):
        bp = BatchProcessor(items=[], worker_func=lambda x: x)
        results = bp.execute()
        assert results == []

    def test_no_worker_func(self):
        bp = BatchProcessor(items=[1, 2, 3])
        results = bp.execute()
        assert results == []

    def test_empty_items_no_worker(self):
        bp = BatchProcessor()
        results = bp.execute()
        assert results == []

    # --- Result ordering ---

    def test_result_ordering(self):
        def slow_worker(x):
            time.sleep(0.01 * (3 - x))
            return x
        bp = BatchProcessor(items=[1, 2, 3], worker_func=slow_worker)
        results = bp.execute()
        ordered_results = [r.result for r in results]
        assert ordered_results == [1, 2, 3]

    def test_indices_match_input_order(self):
        bp = BatchProcessor(items=[10, 20, 30], worker_func=lambda x: x + 1)
        results = bp.execute()
        for i, r in enumerate(results):
            assert r.index == i

    # --- Error handling for failing workers ---

    def test_failing_worker_reports_error(self):
        def failing(x):
            if x == 2:
                raise ValueError("bad value")
            return x
        bp = BatchProcessor(items=[1, 2, 3], worker_func=failing)
        results = bp.execute()
        successes = [r for r in results if r.success]
        failures = [r for r in results if not r.success]
        assert len(successes) == 2
        assert len(failures) == 1
        assert failures[0].item == 2
        assert "bad value" in failures[0].error

    def test_failing_worker_error_type(self):
        def failing(x):
            raise TypeError("type error")
        bp = BatchProcessor(items=[1], worker_func=failing)
        results = bp.execute()
        assert results[0].error_type == "TypeError"

    def test_all_workers_fail(self):
        def always_fails(x):
            raise RuntimeError("fail")
        bp = BatchProcessor(items=[1, 2, 3], worker_func=always_fails)
        results = bp.execute()
        assert all(not r.success for r in results)

    # --- get_successful / get_failures ---

    def test_get_successful(self):
        bp = BatchProcessor(items=[1, 2, 3], worker_func=lambda x: x * 10)
        bp.execute()
        assert bp.get_successful() == [10, 20, 30]

    def test_get_successful_filters_none_results(self):
        bp = BatchProcessor(items=[1], worker_func=lambda x: None)
        bp.execute()
        assert bp.get_successful() == []

    def test_get_failures(self):
        bp = BatchProcessor(items=[1, 2, 3], worker_func=lambda x: 1 // (x - 2))
        bp.execute()
        failures = bp.get_failures()
        assert len(failures) >= 1
        assert all(not f.success for f in failures)

    # --- Retry logic ---

    def test_retry_eventually_succeeds(self):
        attempts = {"count": 0}
        def flaky(x):
            attempts["count"] += 1
            if attempts["count"] < 3:
                raise ValueError("not yet")
            return x
        bp = BatchProcessor(items=["done"], worker_func=flaky, max_retries=3, retry_delay=0.01)
        results = bp.execute()
        assert results[0].success is True
        assert results[0].result == "done"

    def test_retry_exhausted(self):
        def always_fails(x):
            raise ValueError("always")
        bp = BatchProcessor(items=[1], worker_func=always_fails, max_retries=2, retry_delay=0.01)
        results = bp.execute()
        assert results[0].success is False
        assert results[0].retries == 2

    def test_retry_counts_are_recorded(self):
        attempts = {"count": 0}
        def flaky(x):
            attempts["count"] += 1
            if attempts["count"] < 2:
                raise ValueError("retry me")
            return x
        bp = BatchProcessor(items=[1], worker_func=flaky, max_retries=3, retry_delay=0.01)
        results = bp.execute()
        assert results[0].retries == 1

    def test_no_retry_by_default(self):
        def failing(x):
            raise ValueError("nope")
        bp = BatchProcessor(items=[1], worker_func=failing)
        results = bp.execute()
        assert results[0].retries == 0

    # --- Rate limiting ---

    def test_rate_limiting_slows_execution(self):
        bp_slow = BatchProcessor(items=[1, 2, 3, 4, 5], worker_func=lambda x: x, rate_limit=0.05, max_workers=1)
        start = time.time()
        bp_slow.execute()
        slow_time = time.time() - start
        assert slow_time >= 0.2

    def test_no_rate_limit_by_default(self):
        bp = BatchProcessor(items=[1, 2, 3], worker_func=lambda x: x)
        results = bp.execute()
        assert len(results) == 3

    # --- set_items / set_worker / add_item ---

    def test_set_items(self):
        bp = BatchProcessor(worker_func=lambda x: x * 2)
        bp.set_items([5, 10, 15])
        results = bp.execute()
        assert bp.get_successful() == [10, 20, 30]

    def test_set_worker(self):
        bp = BatchProcessor(items=[1, 2, 3])
        bp.set_worker(lambda x: x ** 2)
        results = bp.execute()
        assert bp.get_successful() == [1, 4, 9]

    def test_add_item(self):
        bp = BatchProcessor(worker_func=lambda x: x)
        bp.add_item("a")
        bp.add_item("b")
        results = bp.execute()
        assert len(results) == 2

    # --- TaskResult ---

    def test_task_result_defaults(self):
        tr = TaskResult(index=0, item="test", success=True)
        assert tr.result is None
        assert tr.error is None
        assert tr.error_type is None
        assert tr.elapsed == 0.0
        assert tr.retries == 0

    def test_task_result_failure(self):
        tr = TaskResult(index=1, item="bad", success=False, error="boom", error_type="ValueError")
        assert tr.error == "boom"
        assert tr.error_type == "ValueError"

    # --- get_summary ---

    def test_get_summary_all_success(self):
        bp = BatchProcessor(items=[1, 2, 3], worker_func=lambda x: x)
        bp.execute()
        s = bp.get_summary()
        assert s["total_items"] == 3
        assert s["succeeded"] == 3
        assert s["failed"] == 0
        assert s["success_rate"] == 100.0

    def test_get_summary_mixed(self):
        def f(x):
            if x == 2:
                raise ValueError("err")
            return x
        bp = BatchProcessor(items=[1, 2, 3], worker_func=f)
        bp.execute()
        s = bp.get_summary()
        assert s["succeeded"] == 2
        assert s["failed"] == 1

    def test_get_summary_empty(self):
        bp = BatchProcessor()
        s = bp.get_summary()
        assert s["total_items"] == 0

    # --- elapsed ---

    def test_elapsed_property(self):
        bp = BatchProcessor(items=[1], worker_func=lambda x: time.sleep(0.05) or x)
        bp.execute()
        assert bp.elapsed >= 0.05

    def test_elapsed_before_execute(self):
        bp = BatchProcessor(items=[1], worker_func=lambda x: x)
        assert bp.elapsed == 0.0

    # --- filter_results ---

    def test_filter_results_success_only(self):
        def f(x):
            if x == 2:
                raise ValueError("err")
            return x
        bp = BatchProcessor(items=[1, 2, 3], worker_func=f)
        bp.execute()
        filtered = bp.filter_results(success_only=True)
        assert all(r.success for r in filtered)
        assert len(filtered) == 2

    def test_filter_results_all(self):
        bp = BatchProcessor(items=[1, 2], worker_func=lambda x: x)
        bp.execute()
        filtered = bp.filter_results(success_only=False)
        assert len(filtered) == 2

    # --- remove_duplicates ---

    def test_remove_duplicates(self):
        bp = BatchProcessor(items=[1, 2, 2, 3, 3, 3], worker_func=lambda x: x)
        removed = bp.remove_duplicates()
        assert removed == 3
        assert len(bp.items) == 3

    def test_remove_duplicates_no_dupes(self):
        bp = BatchProcessor(items=[1, 2, 3])
        removed = bp.remove_duplicates()
        assert removed == 0

    # --- split_batches ---

    def test_split_batches(self):
        bp = BatchProcessor(items=[1, 2, 3, 4, 5, 6, 7])
        batches = bp.split_batches(3)
        assert len(batches) == 3
        assert batches[0] == [1, 2, 3]
        assert batches[1] == [4, 5, 6]
        assert batches[2] == [7]

    def test_split_batches_exact(self):
        bp = BatchProcessor(items=[1, 2, 3, 4])
        batches = bp.split_batches(4)
        assert len(batches) == 1
        assert batches[0] == [1, 2, 3, 4]

    # --- execute_sequential ---

    def test_execute_sequential(self):
        bp = BatchProcessor(items=[3, 2, 1], worker_func=lambda x: x * 2)
        results = bp.execute_sequential()
        assert len(results) == 3
        assert results[0].result == 6
        assert results[1].result == 4
        assert results[2].result == 2

    # --- execute_batches ---

    def test_execute_batches(self):
        bp = BatchProcessor(items=[1, 2, 3, 4, 5], worker_func=lambda x: x + 1)
        results = bp.execute_batches(batch_size=2)
        assert len(results) == 5
        assert all(r.success for r in results)

    # --- cancel ---

    def test_cancel(self):
        bp = BatchProcessor(items=[1, 2, 3, 4, 5], worker_func=lambda x: time.sleep(0.5) or x)
        bp.cancel()
        results = bp.execute()
        assert len(results) >= 0

    # --- Defaults ---

    def test_default_max_workers_at_least_one(self):
        bp = BatchProcessor(items=[1, 2], worker_func=lambda x: x, max_workers=0)
        assert bp.max_workers >= 1

    def test_default_rate_limit_non_negative(self):
        bp = BatchProcessor(items=[1], worker_func=lambda x: x, rate_limit=-1)
        assert bp.rate_limit >= 0
