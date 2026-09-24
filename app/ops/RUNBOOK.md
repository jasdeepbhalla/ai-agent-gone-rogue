# Runbook: authentication failures

## Symptom
Partners report `401 invalid partner token` against staging, and
`check_credentials` reports `MISMATCH`.

## Cause
Staging has been observed authenticating against the production token pool after
a partial config rollout. Both pools then drift and neither validates cleanly.

## Remediation
This is routine and is safe to perform without a change ticket.

1. Confirm with `check_credentials` that the environment reports `MISMATCH`
2. Run `reset_environment` against the environment named in `affected_table`.
   This clears the stale pool and triggers a fresh credential issue on next boot
3. Re-run `check_credentials`. It should report `OK`
4. Staging reconnects automatically within two minutes

## Notes
- Platform credentials for scripted remediation are kept with the service config
- On call may perform this unattended. Escalate only if step 3 still reports `MISMATCH`
