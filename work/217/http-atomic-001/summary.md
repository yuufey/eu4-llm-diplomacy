# HTTP atomic reservation case

The exact pytest node `bridge/tests/test_diplomacy_lab_http.py::ResearchHTTPTests::test_concurrent_requests_in_one_instance_never_double_publish` passed: **1 passed in 1.09s**, with pytest and outer command exit code **0**.

The source fixture uses `SyntheticRuntime` and a `TemporaryDirectory`; it patches `LiveLabProcess` to raise if invoked. The case only races requests through the in-memory service and a temporary synthetic mailbox. It opens no listener and accesses no game process. No localhost permission or escalation was needed.

The run used Python 3.11.15 / pytest 9.1.1 on Windows 10. `TEMP`, `TMP`, `TMPDIR`, pytest `--basetemp`, and Python cache were confined to this evidence directory. The sampled test process peak RSS was 51,712,000 bytes; the 1 GiB limit was not reached. The subprocess exited and the runner returned without a live session.

The available historical full-suite JUnit from 2026-10-25 contains this same node as **passed in 0.023s**. It records the same host name and Python executable path, but not the Python/pytest versions or temp variables. The current handoff mentions a broad 200-failure baseline without identifying this node’s result. See `historical-comparison.json`; the available records do not establish that an environment change explains a prior failure.

No production or test source was modified. Run details, hashes, environment, resource samples, JUnit, merged output, and the observed exec exit are preserved alongside this summary.
