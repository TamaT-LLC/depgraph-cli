# Security disclosure dry run

The fixture at
[`security/disclosure-dry-run-v1.json`](../../security/disclosure-dry-run-v1.json)
is a redacted exercise record, not a real vulnerability report. It proves the
ordered handoff from the private reporting route through triage, a private
advisory, private fix, verified release, and coordinated disclosure.

Run the harness with:

```console
cargo xtask test
```

The verifier rejects a missing or reordered phase, an unknown field, malformed
evidence digest, retained raw report, fork secret access, or release credential
access before the verified-release phase. A real exercise must use a fresh
scenario ID and digests, stay inside GitHub Security Advisories, involve the
security and release maintainers, confirm rollback and user remediation, and
publish only the agreed advisory after the fix is available.
