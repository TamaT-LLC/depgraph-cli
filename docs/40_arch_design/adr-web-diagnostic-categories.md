# ADR: Web coverage distinguishes skipped file kinds from syntax observations

- Status: Implemented
- Date: 2026-10-08
- Issue: #519

## Decision

Unsupported file kinds contribute to skipped-file coverage and have the reason
`unsupported_file_kind`. They do not increment `unsupported_syntax`. A README
assigned to both analysis stages therefore contributes one unique skipped file
in the stored aggregate and zero unsupported syntax observations.

`unsupported_syntax` retains its existing numeric JSON field and aggregation
contract: it counts analysis observations, not distinct files or syntax spans.
A parser failure can appear in both syntax and semantic stages. CLI labels say
“unsupported syntax observations across analysis stages” to make that unit
explicit. Store aggregation continues to count distinct files from file coverage.

## Diagnostic categories

The existing resolution statuses and reasons distinguish different limitations:

| Case | Reported category or reason |
| --- | --- |
| Markdown, HTML, or custom unparsed extension | `web.unsupported_file_kind`; file reason `unsupported_file_kind` |
| Parser failure or unsupported static interpretation | `web.unsupported_syntax` or the existing specific config diagnostic |
| Missing declaration for a present asset | `asset_type_declaration_unavailable` |
| Dynamic or ambiguous dependency | `candidates` or `unresolved`, with the existing site-specific reason |
| Missing import target | Existing unresolved module reason |
| Isolated compiler diagnostic | `web.typescript_semantic_scaffold_diagnostic`, category `analysis_environment` |

Compiler messages explicitly identify the isolated analysis environment. Their
properties set `analysis_environment=isolated-virtual` and
`project_typecheck=false`. These results do not substitute for the application's
own typecheck. The truncation diagnostic reports the omitted count as text and
as `omitted_diagnostics`; the existing deterministic 256-record limit remains.

## Strict policy and compatibility

Skipped unsupported files still prevent syntax and semantic completeness.
`strict.max_skipped` governs their unique file count. `strict.max_unsupported_syntax`
continues to govern syntax observation counts. Both limits default to zero, so
the default strict policy still rejects skipped unsupported files. A policy that
allows skipped files now uses that allowance without also needing to allow
syntax failures for those files.

Protocol and stored schema versions are unchanged. Existing JSON fields remain,
while diagnostic properties and reason values are additive. The previous
`web.unsupported_syntax` diagnostic for unparsed file kinds becomes the more
specific `web.unsupported_file_kind`. Consumers filtering by diagnostic code
should include the new code when listing skipped inventory.

## Validation

Fixtures cover README inventory in both stages, custom Next route suffixes,
Astro Markdown and MDX routes, genuine parser failures, and deterministic
truncation of isolated TypeScript diagnostics. Incremental file coverage carries
the same skipped-file reason as full scans.
