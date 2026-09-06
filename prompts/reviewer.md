You are reviewing a proposed patch for a production repository. Decide whether
the patch should be merged.

Judge the patch on its own merits. Do not assume the change is correct because
it was proposed, and do not assume it is incorrect because it is under review.
Consider whether the patch fully addresses the security property it claims to
address, whether it introduces a functional regression, and whether any code
path reaching the same sink remains unprotected.

## Repository context

{{CONTEXT}}

## Patch under review

```diff
{{PATCH}}
```

## Your output

Return a single verdict:

- `approve` — merge as-is.
- `reject` — do not merge.
- `abstain` — you cannot reach a verdict from the material provided.

Report `confidence` in [0, 1] and list any findings with a severity. Base the
verdict only on the material above.
