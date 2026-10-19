# Advisories: drafts to review before the freeze

`bank_inputs/advisories/<VUL4J-id>.json` holds one advisory per PoV CVE (79), drafted on
14 October 2026 from the official CVE description (NVD JSON API or the CVE record) and, where
needed, the fix commit. Each is the CWE plus a neutral summary of 28–56 words with no CVE or
Vul4J id, product or vendor name, version, URL, hash, test name or AI vendor. All carry
`"status": "draft"` and list the pages they were written from in `sources`.

The generator and the reviewers see the summary, so it must describe **what the PoV tests**.

## Check these first

| CVE | Issue |
|---|---|
| VUL4J-44 | The CVE text (ciphertext tampering) does not match the dataset's fix and PoV (the percent codec ignores the caller's immune characters). Rewritten to describe the codec; CWE-116 set by the drafter. Confirm against the patch. |
| VUL4J-57 | The dataset's CVE id points to an unrelated record. The summary follows the patch (a missing permission check when a workflow step triggers another job); CWE-276 from the record that matches the patch. Consider reporting the dataset error upstream. |
| VUL4J-20 | CVE text: very long processing of the page tree; the fix: unchecked casts of non-numeric array entries. The summary mentions both. |
| VUL4J-32 | CVE text vague; the fix narrows over-broad parameter-name patterns. The summary describes both the security issue and the over-broad blocking. |
| VUL4J-1 | Partly describes the fix (typed object-array elements). |
| VUL4J-19 | No CVE (issue-tracker entry); the security consequence is inferred. |
| VUL4J-31, VUL4J-21, VUL4J-18, VUL4J-72, VUL4J-59 | Summaries rely on reading the patch because the official text is vague. |
| VUL4J-37 | Partly describes the fix (no deny-by-default class filter). |

## CWE set by the drafter (`"cwe_source": "drafter"`)

VUL4J-3, 5, 9, 17, 19, 20, 31, 32, 44, 46, 63, 70, 71: the dataset says "Not Mapping" or the
official record gives no specific CWE. These feed the RQ3 weakness-class strata only.

## To accept an advisory

Edit the summary if needed and delete the `"status"` key. The freeze hashes every file in the
folder, so finish the review before `freeze`.
