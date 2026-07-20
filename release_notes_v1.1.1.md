### Fixed

- **The pipeline could not start from a clean install.** `enrich.py`,
  `graylog_fetch.py`, and `ntopng_fetch.py` imported `perf_diag`, an internal
  diagnostic counter module that is deliberately not part of the distribution.
  A fresh clone therefore failed at import with
  `ModuleNotFoundError: perf_diag` before the service could start.

  **This affected 1.0.0 and 1.1.0.** It was invisible in development because
  the module is present there.

  The import is now guarded and falls back to a no-op stub covering the full
  call surface, so the absence of the diagnostic module can never stop the
  pipeline. Behavior is unchanged where the module is present.

  `perf_diag` remains excluded from the distribution deliberately: it takes a
  lock on the per-alert path when enabled, which is exactly the class of
  worker-serialization point removed during the concurrency hardening work.
  The instrumentation call sites stay in place as permanent hooks — dropping
  the module into an install enables them, and its absence disables them.

  No configuration change is required, and no configuration key is affected.


