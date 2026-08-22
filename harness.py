"""Moved to `hp/providers.py`.

This module used to hold `dispatch(provider, model, prompt, temperature)`. It was
replaced rather than extended, because the old signature could not express the
things the experiment turned out to need:

* provider-native structured output, so a verdict is enforced rather than
  regex-scraped out of prose;
* a status taxonomy that distinguishes a timeout from a truncated response from
  a schema violation from a 400 -- four facts with different scientific meanings
  and different retry policies, which the old single `status: "error"` flattened
  into one;
* request timeouts and classified backoff, with each operational attempt logged
  separately so the missingness structure stays auditable.

Kept as a shim so nothing that still imports it breaks silently.
"""

import warnings

from hp.providers import PROVIDERS, call_once, call_with_retries  # noqa: F401

__all__ = ["PROVIDERS", "call_once", "call_with_retries", "dispatch"]


def dispatch(provider, model, prompt, temperature, timeout_s=120, max_tokens=2048):
    """Deprecated. Use `hp.providers.call_with_retries`."""
    warnings.warn(
        "harness.dispatch is deprecated; use hp.providers.call_with_retries, "
        "which enforces the verdict schema and classifies failures.",
        DeprecationWarning,
        stacklevel=2,
    )
    return call_once(
        {"provider": provider, "model": model},
        prompt,
        {"temperature": temperature, "timeout_s": timeout_s, "max_tokens": max_tokens},
    )
