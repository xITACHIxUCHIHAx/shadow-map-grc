"""Execute and persist independent targets in a scan batch."""

from time import monotonic

from scanner.batch_storage import (
    create_batch,
    start_batch_item,
    save_module_result,
    save_nmap_result,
    finish_batch_item,
    finish_batch,
)


def execute_batch(db_factory, module, profile, targets,
                  validator, scanner):
    """
    Create a batch, then validate, execute and persist each target.

    Each target has its own database transaction. A failed target does not
    prevent subsequent targets from being processed.
    """
    with db_factory() as db:
        batch_id = create_batch(db, module, profile, targets)
        items = db.execute(
            """
            SELECT id, position, target
            FROM scan_batch_items
            WHERE batch_id = ?
            ORDER BY position
            """,
            (batch_id,),
        ).fetchall()

    for item in items:
        item_id = item["id"]
        raw_target = item["target"]
        started_at = None
        started_clock = monotonic()
        result = None
        error = None
        result_type = ""
        result_record_id = None
        request_id = None
        status = "Failed"
        target = raw_target

        with db_factory() as db:
            start_batch_item(db, item_id)

        try:
            from scanner.batch_storage import now_utc
            started_at = now_utc()

            target = validator(raw_target)
            result = scanner(target)

            status = (
                result.get("status", "Completed")
                if isinstance(result, dict)
                else "Completed"
            )
            if status not in ("Completed", "Partial", "Failed"):
                status = "Failed"
            if status == "Failed" and isinstance(result, dict):
                error = result.get("error") or "Scanner reported failure."

        except Exception as exc:
            error = str(exc) or exc.__class__.__name__

        duration = max(0.0, monotonic() - started_clock)

        try:
            with db_factory() as db:
                if module == "nmap" and started_at:
                    result_type, result_record_id, request_id = (
                        save_nmap_result(
                            db, target, profile, status, started_at,
                            duration, result, error,
                        )
                    )
                elif module in ("web_security", "threat_intel"):
                    if started_at is None:
                        from scanner.batch_storage import now_utc
                        started_at = now_utc()

                    result_type, result_record_id = save_module_result(
                        db, module, target, status, started_at,
                        duration, result, error,
                    )

                finish_batch_item(
                    db, item_id, status, duration,
                    result_type, result_record_id, request_id, error,
                )

        except Exception as exc:
            # Preserve the failure on the batch item if result persistence fails.
            error = (
                (error + "; " if error else "")
                + "Result persistence failed: "
                + (str(exc) or exc.__class__.__name__)
            )
            with db_factory() as db:
                finish_batch_item(
                    db, item_id, "Failed", duration, error=error,
                )

    with db_factory() as db:
        summary = finish_batch(db, batch_id)

    return batch_id, summary
