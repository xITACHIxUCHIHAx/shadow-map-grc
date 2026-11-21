"""Shared resource limits for multi-target assessment runs."""

import math
import time

import config


class UnifiedRunLimitError(RuntimeError):
    """Raised when a shared assessment-run limit has been reached."""


class UnifiedWebRunGuard:
    """Enforce aggregate HTTP request and elapsed-time limits."""

    def __init__(
        self,
        maximum_requests=None,
        timeout_seconds=None,
        clock=None,
    ):
        if maximum_requests is None:
            maximum_requests = config.WEB_UNIFIED_MAX_REQUESTS

        if timeout_seconds is None:
            timeout_seconds = config.WEB_UNIFIED_TIMEOUT_SECONDS

        if (
            not isinstance(maximum_requests, int)
            or isinstance(maximum_requests, bool)
            or not 1 <= maximum_requests <= 12500
        ):
            raise ValueError("Invalid Unified Web Security request limit.")

        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or not 1 <= timeout_seconds <= 7200
        ):
            raise ValueError("Invalid Unified Web Security deadline.")

        self.maximum_requests = maximum_requests
        self.timeout_seconds = float(timeout_seconds)
        self.clock = clock or time.monotonic
        self.started_at = self.clock()
        self.deadline = self.started_at + self.timeout_seconds
        self.used_requests = 0

    @property
    def remaining_requests(self):
        return self.maximum_requests - self.used_requests

    @property
    def remaining_seconds(self):
        return max(0.0, self.deadline - self.clock())

    def check(self):
        if self.clock() >= self.deadline:
            raise UnifiedRunLimitError(
                "Unified Web Security run deadline exceeded."
            )

        if self.used_requests >= self.maximum_requests:
            raise UnifiedRunLimitError(
                "Unified Web Security aggregate HTTP request limit exhausted."
            )

        return self.remaining_seconds

    def consume(self):
        self.check()
        self.used_requests += 1
        return self.used_requests

    def request_timeout(self, connect_timeout, read_timeout):
        """Cap connect/read timeouts by the remaining run time."""
        remaining = self.check()
        return (
            min(float(connect_timeout), remaining),
            min(float(read_timeout), remaining),
        )
