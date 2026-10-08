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

## Reviewed refresh: scan resolution accuracy (2026-10-08)

The #516–#523 changes were compared with the `v0.6.2` main-line source before
refreshing identities. Clone groups decreased from 104 to 102, instances from
218 to 214, and duplicated lines from 3,217 to 3,146. Of the 23 fragments
reported as new after identity renumbering, 21 were byte-identical to existing
source. The other two retain existing validation traversal/range checks with
the new `type_query` occurrence. Their existing duplication is accepted here;
no duplication threshold or exclusion was changed.

The 12 newly identified complexity findings are existing resolver functions
and an existing binding visitor. Ten complete bodies are byte-identical. The
file-base resolver adds the dotted-stem lookup choice with unchanged reported
complexity (10 cyclomatic / 9 cognitive). The dependency resolver adds asset
fallback and importer-reason propagation, increasing from 48/61 to 51/67.
That small increase in the existing resolver is explicitly accepted for these
fixes. Newly added declaration-loader helpers and importer parsing helpers were
split until none introduced a complexity finding. Gate scripts and thresholds
remain unchanged.
