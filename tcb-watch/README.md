# tcb-watch

A weekly check of the SEV-SNP firmware versions Azure East US reports in attestation tokens.

`.github/workflows/tcb-watch.yml` runs on Mondays at 15:00 UTC and on demand. It signs in to Azure with a federated
credential for this repository's `main` branch (no stored secret), deploys the attestation sidecar as a confidential
container group in `aseryx-enclave-spike`, reads one token, checks Microsoft's signature on it with `verify.mjs`, and
deletes the group.

Each run appends one line to `tcb-watch/log.jsonl` on the `tcb-watch` branch:

```json
{"date":"2026-11-24T15:00:00Z","region":"eastus","chipFamily":"Genoa","snpfw":23,"microcode":84,"bootloader":10,"tee":0,"patched":false}
```

`patched` is true when `snpfw` is at least 30, the SNP firmware AMD's bulletin AMD-SB-3059 lists as the fix for Genoa. The run
fails when `patched` is true, when the deployment or the token step fails, and when a group is left behind.

`node --test tcb-watch/verify.test.mjs` runs the token reader's tests, which use a real East US token.
