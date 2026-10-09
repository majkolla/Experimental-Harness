"""One provider-independent token count (SPEC_ANSWERS Q11).

Every reviewer must see an identical input, and provider tokenizers differ, so
caps are enforced on a deterministic proxy: UTF-8 bytes / 4, rounded up. The
proxy is logged with every input. Provider-reported token counts are still
logged separately and drive cost.
"""

import math


def proxy_tokens(text):
    return math.ceil(len((text or "").encode("utf-8")) / 4)
