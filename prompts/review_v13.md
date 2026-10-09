You are reviewing a pull request for a production Java repository. Decide whether the patch should be merged.

Approve only if the patch fully fixes the reported issue and introduces no new vulnerability and no functional regression. Otherwise reject. Abstain only if the material below is not enough to reach a verdict.

## Pull request description

{{PR_DESCRIPTION}}

## Patch

```diff
{{DIFF}}
```

## Changed code after the patch, with surrounding context

{{CONTEXT}}
{{EVIDENCE_SECTION}}
## Your answer

Return:

- `verdict`: `approve`, `reject` or `abstain`;
- `risk`: an integer from 0 to 100, your estimate of the chance that the patched code is still exploitable for the reported issue, or has a new vulnerability;
- `justification`: at most 150 words.

Base your answer only on the material above.
