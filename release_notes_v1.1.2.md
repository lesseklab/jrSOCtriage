### Fixed

- **The service could not start from a clean install.** `main.py` imports
  `lag_logger` unconditionally during startup, but the module was not included
  in the distribution, so the pipeline raised `ModuleNotFoundError: lag_logger`
  the moment the service was started.

  **This affected 1.0.0, 1.1.0, and 1.1.1.** It is distinct from the 1.1.1 fix
  and was not covered by it: the 1.1.1 issue failed at *module import*, while
  this one failed later, at *service start*, so a successful `import main` did
  not reveal it.

  `lag_logger.py` is now part of the distribution, where it belongs. It is
  product code rather than tooling: it provides the `NullLagState` object used
  on the default path when observability is disabled, and it implements the
  `[LAG]` diagnostic line documented in the configuration reference and the
  FAQ, controlled by `observability.lag_log_interval_seconds`.

  No configuration change is required. `[LAG]` output remains off by default.


