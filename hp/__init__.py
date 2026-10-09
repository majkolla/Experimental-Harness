"""Review-harness: measuring correlated false approval in multi-reviewer LLM code review.

Two studies live here (see README.md and docs/study.html):

* the v1.3 study (current): study_config, logs, tokens, leaks, synthworld,
  engine, bank/, review/, analysis/, driven by study.py;
* Experiment 1 (legacy, merged into v1.3): config, design, dataset, report,
  driven by main.py and analyze.py; kept runnable and unchanged.

Layering (nothing below may import from above):

    schema, tokens          <- output contracts, status taxonomy, token proxy
    config, study_config    <- legacy config / study config and its gauntlet
    logs, leaks, synthworld <- log schemas, oracle deny list, synthetic world
    design                  <- legacy schedule construction
    providers               <- one call in, one status-tagged record out
    runner, engine          <- legacy runner / shared study dispatcher
    bank                    <- Stages 1-4 (Vul4J, generation, classes, twins)
    review                  <- Stage 5 (e0, packets, schedule, dispatch)
    estimators, bootstrap, dataset, report  <- legacy offline analysis
    analysis                <- v1.3 offline analysis
"""

HARNESS_VERSION = "0.3.0"
