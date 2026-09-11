# Empty HTTP identity requests

Real Node HTTP represents a bodyless POST as an empty readable stream. Rejecting stream
presence alone makes valid private identity checks fail with401, although in-memory tests pass.

Chosen fix: require zero bytes with a one-second deadline and at most eight empty chunks.
Reject declared nonzero length before reading, reject any byte, cancel/release the reader and
retain all JWT, scope, wallet, merchant and revocation checks. Do not change POST to GET or
trust Content-Length alone. The helper never buffers request payloads.

Verification includes the actual Node HTTP adapter: valid empty POST succeeds, nonempty POST
fails. Unit tests cover empty, forged zero-length, stalled and pathological streams. Loopback
HTTP is a test transport only; deployed endpoints continue using HTTPS.
