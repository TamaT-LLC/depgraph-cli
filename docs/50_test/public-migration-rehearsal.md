# Public migration rehearsal

This runbook rehearses a private-to-public transition only in a non-sensitive
temporary repository.
It does not authorize or automate a visibility change for
`TamaT-LLC/depgraph-cli`.
The harness mode is fixed to
`temporary-repository-no-production-actuator`.

## Preconditions

The repository administrator creates a temporary organization repository whose
plan and enabled GitHub features are equivalent to the production repository.
The fixture commit, refs, issues, release, package, and community metadata must
be synthetic and non-sensitive.
The administrator records SHA-256 digests for the temporary-repository
attestation, plan/features comparison, backup, settings export, each transition
checkpoint, and the anonymous smoke report.
Raw tokens, webhook URLs, deploy keys, credentials, repository names, and
private settings exports never enter the report.

The production repository must retain its original visibility for the entire
rehearsal.
Any observation that it changed is an immediate no-go.

## Exact rehearsal sequence

The harness accepts only this order:

1. `verify_temporary_target`: prove that the target is not the production
   repository, that the temporary-repository attestation is present, and that
   the plan/features digest matches production.
2. `capture_backup_and_settings`: create a fresh mirror and a settings export,
   assign restore and containment owners, and retain only their digests in the
   report.
3. `freeze_writes`: stop pushes, merges, releases, package publication, app
   writes, and administrative changes in the temporary repository.
4. `change_visibility`: change only the temporary repository to public and
   record the checkpoint digest.
5. `restore_rulesets`: recreate and enable the desired branch and tag rulesets,
   including required check contexts and their GitHub App source.
6. `enable_security`: enable private vulnerability reporting, advisories,
   secret scanning, push protection, dependency graph, Dependabot, and code
   scanning as supported by the equivalent plan.
7. `verify_desired_settings`: run the read-only
   `github-settings-desired-v1` verifier and require an `allow` result.
8. `run_anonymous_smoke`: use an unauthenticated session and network path to
   verify clone, source archive, README/docs, community links, issue templates,
   public Actions, Releases, and package download.
9. `reopen_writes`: reopen temporary-repository writes only when both settings
   verification and every anonymous smoke check passed.
10. `cleanup_temporary_repository`: preserve the digest-only report, remove or
    restore the temporary repository according to the rehearsal owner, and
    confirm cleanup.

A missing, failed, duplicated, or out-of-order checkpoint is a no-go.
After a no-go, only `cleanup_temporary_repository` may run.
The report remains `frozen` and `contained`; any other later activity is
recorded as `activity_after_no_go`.

## Anonymous smoke contract

The smoke report is complete only when all of these closed fields are true:

- `clone`
- `source_archive`
- `readme_and_docs`
- `community_links`
- `issue_templates`
- `actions`
- `release`
- `package_download`

The anonymous session must not reuse an organization login, SSH agent, API
token, package credential, browser session, or cached private clone.
The report stores only the smoke evidence digest.

## Evidence and cleanup

The versioned input schema is
`schemas/public-migration-rehearsal-input-v1.schema.json`.
The evaluator preserves checkpoint phase order and SHA-256 evidence digests,
hashes the temporary repository identifier, and emits a canonical report.
A failure report names the first deterministic no-go phase, keeps writes
frozen, marks containment active, and states whether cleanup is completed or
still required.

Production execution requires a separate final audit, explicit organization
owner authorization, a named change window, and the Gate 8 evidence described
in the public OSS release governance ADR.
