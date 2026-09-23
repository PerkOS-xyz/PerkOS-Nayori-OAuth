# Production private-evidence identity activation

OAuth already implements the required wallet-linked identity boundary. Production activation is
configuration and provisioning, not a broader authorization feature.

Set `PRIVATE_EVIDENCE_IDENTITY_ENABLED=true` only after Platform production private evidence is
ready. Provision a dedicated OAuth client bound to the reviewed mainnet Evaluator wallet with
exactly `evidence:read`; do not reuse merchant, SDK, operator or QA credentials. Store the
one-time client secret only in the Evaluator mode-600 secret file.

Confirm discovery advertises `evidence:read`, token issuance rejects every ungranted scope and
`POST /oauth/evidence/identity` returns the current active wallet/client binding with
`Cache-Control: no-store`. Disabling the client or removing its grant must invalidate subsequent
identity checks even while an already issued JWT remains cryptographically valid.

OAuth never receives a Stacks private key and cannot sign `record-decision`. Platform must still
perform its own JWT, merchant and current on-chain job authorization. Keep public evaluator
admission disabled during the canary.
