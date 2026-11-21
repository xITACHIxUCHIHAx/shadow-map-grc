import pytest

from scanner.run_limits import (
    UnifiedRunLimitError,
    UnifiedWebRunGuard,
)


class FakeClock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def test_guard_tracks_aggregate_requests_across_targets():
    guard = UnifiedWebRunGuard(
        maximum_requests=3,
        timeout_seconds=60,
    )

    assert guard.consume() == 1
    assert guard.consume() == 2
    assert guard.remaining_requests == 1
    assert guard.consume() == 3

    with pytest.raises(
        UnifiedRunLimitError,
        match="aggregate HTTP request limit exhausted",
    ):
        guard.consume()


def test_guard_enforces_monotonic_deadline():
    clock = FakeClock()
    guard = UnifiedWebRunGuard(
        maximum_requests=10,
        timeout_seconds=5,
        clock=clock,
    )

    clock.advance(4)
    assert guard.remaining_seconds == 1
    assert guard.check() == 1

    clock.advance(1)
    with pytest.raises(
        UnifiedRunLimitError,
        match="deadline exceeded",
    ):
        guard.check()


def test_request_timeouts_are_capped_by_remaining_time():
    clock = FakeClock()
    guard = UnifiedWebRunGuard(
        maximum_requests=10,
        timeout_seconds=4,
        clock=clock,
    )

    clock.advance(1)
    assert guard.request_timeout(3, 7) == (3.0, 3.0)


@pytest.mark.parametrize(
    "maximum, timeout",
    [
        (0, 10),
        (12501, 10),
        (True, 10),
        (10, 0),
        (10, 7201),
        (10, float("inf")),
    ],
)
def test_guard_rejects_invalid_limits(maximum, timeout):
    with pytest.raises(ValueError):
        UnifiedWebRunGuard(
            maximum_requests=maximum,
            timeout_seconds=timeout,
        )
