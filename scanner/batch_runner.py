"""Sequential, independently validated batch execution."""

from dataclasses import dataclass
from time import monotonic


MAX_BATCH_TARGETS = 25


@dataclass
class BatchItemResult:
    position: int
    target: str
    status: str
    duration_seconds: float
    result: object = None
    error: str = ""


def parse_batch_targets(value, max_targets=MAX_BATCH_TARGETS):
    """Parse newline-separated targets without silently dropping duplicates."""
    if not isinstance(value, str):
        raise ValueError("Enter targets, one per line.")

    targets = [
        line.strip()
        for line in value.splitlines()
        if line.strip()
    ]

    if not targets:
        raise ValueError("Enter at least one target.")

    if len(targets) > max_targets:
        raise ValueError(
            f"A batch can contain at most {max_targets} targets."
        )

    seen = set()
    duplicates = []

    for target in targets:
        key = target.casefold()
        if key in seen:
            duplicates.append(target)
        seen.add(key)

    if duplicates:
        raise ValueError(
            "Duplicate targets are not allowed: "
            + ", ".join(duplicates)
        )

    return targets


def run_batch(targets, validator, scanner, clock=monotonic):
    """
    Validate and execute each target independently.

    A validation or scanner failure is recorded for that target; processing
    continues with the next target. Scanner results may report Partial status.
    """
    results = []

    for position, raw_target in enumerate(targets, start=1):
        target = str(raw_target).strip()
        started = clock()

        try:
            validated_target = validator(target)
            scan_result = scanner(validated_target)

            status = "Completed"
            if isinstance(scan_result, dict):
                reported_status = scan_result.get("status", "Completed")
                status = (
                    reported_status
                    if reported_status in ("Completed", "Partial")
                    else "Failed"
                )

                if status == "Failed":
                    error = str(
                        scan_result.get("error")
                        or "Scanner reported an unsuccessful result."
                    )
                    results.append(
                        BatchItemResult(
                            position=position,
                            target=validated_target,
                            status="Failed",
                            duration_seconds=max(0.0, clock() - started),
                            result=scan_result,
                            error=error,
                        )
                    )
                    continue

            results.append(
                BatchItemResult(
                    position=position,
                    target=validated_target,
                    status=status,
                    duration_seconds=max(0.0, clock() - started),
                    result=scan_result,
                )
            )

        except Exception as exc:
            results.append(
                BatchItemResult(
                    position=position,
                    target=target,
                    status="Failed",
                    duration_seconds=max(0.0, clock() - started),
                    error=str(exc) or exc.__class__.__name__,
                )
            )

    return results


def summarize_batch(results):
    """Return stable aggregate counts and an overall batch status."""
    completed = sum(item.status == "Completed" for item in results)
    partial = sum(item.status == "Partial" for item in results)
    failed = sum(item.status == "Failed" for item in results)

    if failed == len(results):
        status = "Failed"
    elif failed or partial:
        status = "Partial"
    else:
        status = "Completed"

    return {
        "status": status,
        "total_targets": len(results),
        "completed_targets": completed,
        "partial_targets": partial,
        "failed_targets": failed,
    }
