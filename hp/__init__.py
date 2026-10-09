"""Review-harness: measuring correlated false approval in multi-reviewer LLM code review.

Layering (nothing below may import from above):

    schema   <- verdict contract, status taxonomy, strict parsing
    config   <- load + validate experiment.json and the task bank
    design   <- pure schedule construction + mechanical balance guarantees
    providers<- one network call, one dict back
    runner   <- execution, resume, provenance, append-only log
    estimators, bootstrap, report  <- offline analysis, log is read-only input
"""

HARNESS_VERSION = "0.2.0"
