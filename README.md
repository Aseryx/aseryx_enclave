# aseryx_enclave

The workload that Aseryx runs inside an AMD SEV-SNP confidential container on Azure Container
Instances. It computes appraisals, threshold answers and dispute checks over a dataset's decrypted
bytes without any operator, Aseryx included, being able to read them.

This repository is public so anyone can inspect the code the owner consents to.

## What the workload does

One container runs one job and exits (`harness/src/main.rs`). The steps, each with the error code it
reports on failure (`harness/src/error_code.rs`):

1. **Claim** (`claim.rs`). The container has no job data, because a job id in its environment would
   change the policy hash. It generates two keys in memory, attests them to Azure Attestation through the
   container group's sidecar (token 1), and the API assigns the oldest unclaimed job that fits. It
   attests the same keys again with the job id (token 2).
2. **Inputs and consent** (`job.rs`). It fetches the job's inputs from the API's `attested-appraisal`
   function and checks the owner's consent against the chain registry.
3. **Key release** (`lit.rs`). The decrypt Lit Action checks the consent's signer, the workload identity, the
   job and the firmware, and releases the dataset key sealed to a key that exists only inside the
   container. The harness forwards the proof and opens the answer.
4. **Chunks** (`store.rs`, `pipeline.rs`). It fetches the encrypted chunks from IPFS, keeps only
   ciphertext on disk, and for every pass decrypts, decompresses and streams the plaintext to the engine in
   slices. After each pass the SHA-256 of what was fed must equal the registered plaintext hash.
5. **Engine** (`engine.rs`). The `aseryx-engine` static library is linked into the harness and called through
   a C ABI. It reads and writes only the bytes it is given. Every run has a deadline, and a watchdog ends the
   process when a run is still open after it.
6. **Proof** (`prove.rs`). The engine's witness is proved with Groth16 over circuit artifacts pinned by
   SHA-256 in `harness/circuit-pins.json`; the workload checks its own proof against the verification key.
7. **Result** (`result.rs`, `metrics.rs`). A flat canonical JSON object is signed by the result key and posted
   with a signed metrics object. The API recomputes the digest and checks the signature against the key in the
   attestation. Nothing else leaves the container.

Exit status 0 means the result was posted, 1 that the job failed and its error code was posted when the API
could be reached, and 2 that the workload could not start.

### Job kinds

| Kind | What it computes |
|---|---|
| Appraisal | The tabular_v12 Score, data label and hashes of the dataset, and the Groth16 proof |
| Threshold | One answer per check, over the dataset and its label, which the owner reviews and approves before it is released |
| Dispute | The buyer's evidence, encrypted in the buyer's browser under a fresh key, is checked in the container: the file against the consent's evidence hash and the label against the licence's label hash (`evidence_mismatch` and `label_mismatch_evidence` otherwise), then a label check or a threshold count (`harness/src/job/dispute.rs`). The workload signs what the engine found and the API decides |

The result is version 2: it names the engine as the native library (`engine`, `engineVersion`,
`engineLibrarySha256`).

## What an owner consents to

The workload identity is the SHA-256 of the confidential computing policy generated for the image. The
policy fixes the image and every `ENCLAVE_*` variable by its exact value, and blocks shell, exec and
standard streams. The engine library is pinned by its SHA-256 in `ENCLAVE_ENGINE_SHA256`, and the harness
starts only when that equals the hash of the library it was built with. The consent names the identity, the
minimum firmware, the job and its expiry. The API refuses a consent that names another identity or older
firmware than the release, and the decrypt action releases a key only to a workload whose attestation matches.

## Settings

The settings are environment variables of the container, so they are part of the policy:
`ENCLAVE_API_URL`, `ENCLAVE_RPC_URLS`, `ENCLAVE_REGISTRY`, `ENCLAVE_CHAIN_ID`, `ENCLAVE_IPFS_GATEWAYS`,
`ENCLAVE_ARTIFACTS_URL`, `ENCLAVE_ENGINE_SHA256`, `ENCLAVE_MEMORY_GB`, `ENCLAVE_APPRAISAL_CIRCUIT`,
`ENCLAVE_ENGINE_DEADLINE_SECS`, `ENCLAVE_PARALLEL_FETCHES`, `ENCLAVE_CACHE_DIR`, `ENCLAVE_SIDECAR_URL` and
`ENCLAVE_MAA_ENDPOINT` (`harness/src/config.rs`). A setting without a default must be present, and a
malformed value is refused.

## Build and test

`make check` runs every gate: format, clippy with warnings as errors, the tests against the pinned circuits
(`make circuits` downloads them) and the aseryx-engine goldens in `harness/tests/tabular`, the docs with
warnings as errors, the policy tests and a secret scan. `make help` lists each target.

## Image

The `image` workflow builds the image twice from scratch and fails unless both builds have the same
digest. A manual run on `main` with `publish` set copies the verified image to
`ghcr.io/aseryx/aseryx-enclave` under the tag `sha-<first 12 characters of the commit>` and checks
that the registry holds the digest the builds produced. The package is made public in the
repository owner's package settings.

The files' timestamps in the image are the Unix time in `SOURCE_DATE_EPOCH`, a file in the repository
root, not the time of a commit, so the image digest and the policy hash depend only on the build inputs
(`Dockerfile`, `Cargo.toml`, `Cargo.lock`, `harness`, `engine`, `engine-native`, `SOURCE_DATE_EPOCH`) and do not change with a
commit, a rebase or a squash merge that leaves them alone.

## Release

A release is the image, the engine library it links and the policy generated from them. The `policy` workflow
generates the production policy at three container sizes, twice each, anchors every regular-expression
environment rule, checks it with `scripts/check-policy.py` and fails unless every size and run gives one hash.
Its artifact `release-policy` holds the policy to deploy and its hash, which is the workload identity that the
orchestrator (`aseryx_zk_server`) and the API pin. The engine library in `engine/` is the `aseryx_engine`
release asset, recorded with its SHA-256 and build record in `engine/SOURCE.json`.
