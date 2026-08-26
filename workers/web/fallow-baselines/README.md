# Fallow quality baselines

`dupes.json` and `health.json` record the production Web worker state after
WEB-REFACTOR-TASK-001 through WEB-REFACTOR-TASK-004. `pnpm quality` suppresses
only findings with the same saved identity; a new clone or complex function
still fails the gate.

Do not update a baseline just to make CI pass. Review the new finding first,
then regenerate only the affected file after accepting the debt explicitly:

```sh
pnpm exec fallow dupes --production --save-baseline fallow-baselines/dupes.json
pnpm exec fallow health --production --complexity --baseline-mode identity \
  --save-baseline fallow-baselines/health.json
```

The Fallow configuration has no `extends` entry. Its local package schema and
the exact dependency version in `pnpm-lock.yaml` keep the gate offline and
reproducible; telemetry is not part of this workflow.
