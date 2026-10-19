"""Running bank-stage items (CVEs, attempts) several at a time.

Each item's function logs its own row the moment it is done. On Ctrl-C the
runner's containers are killed (`runner.interrupt()`), queued items are
cancelled and in-flight items raise InfraError, so nothing half-done is logged.
An InfraError in one item does not stop the others; the first one is re-raised
at the end, so the stage exits non-zero and a resumed run retries those items.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed

from .vul4j import InfraError


def run_items(items, fn, jobs, runner=None):
    items = list(items)
    if jobs <= 1:
        return [fn(i) for i in items]
    out, errors = {}, []
    pool = ThreadPoolExecutor(max_workers=jobs)
    futures = {pool.submit(fn, item): k for k, item in enumerate(items)}
    try:
        for f in as_completed(futures):
            try:
                out[futures[f]] = f.result()
            except InfraError as exc:
                errors.append(exc)
    except KeyboardInterrupt:
        stop = getattr(runner, "interrupt", None)
        if stop is not None:
            stop()
        pool.shutdown(wait=True, cancel_futures=True)
        raise
    except BaseException:
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    pool.shutdown(wait=True)
    if errors:
        raise InfraError(f"{len(errors)} item(s) hit an infrastructure failure and were not "
                         f"logged (run again to retry them); first: {errors[0]}")
    return [out[k] for k in sorted(out)]
