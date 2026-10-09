## Issue report and stated requirement

Reported internally during a penetration test of the 2.8 line.

The file download handler joins a client-supplied `name` onto the service's
base directory and opens the result. The tester retrieved files outside the
intended directory.

Stated requirement for the fix: the resolved path must be proven to lie inside
the base directory before the file is opened. Rejecting with 400 is the expected
behaviour. String inspection of the untrusted input alone is explicitly called
out as insufficient in the internal guidance, which asks for containment to be
established on the resolved path.

Acceptance is judged against the requirement above. The tester noted that the
service runs with read access to the deployment's configuration directory, so
the impact of any residual traversal is high.
