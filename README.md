# aseryx_enclave

The workload that Aseryx runs inside an AMD SEV-SNP confidential container on Azure Container
Instances. It computes appraisals and threshold answers over a dataset's decrypted bytes without any
operator, Aseryx included, being able to read them.

This repository is public so anyone can inspect the code the owner consents to.

Status: under construction. The first work is a spike that measures the platform.

## Engine

The appraisal engine is the `aseryx-engine` crate's static library (`engine/libaseryx_engine_ffi.a`, the asset of an
`aseryx_engine` release, with its `.sha256`, its `.build.txt` and `SOURCE.json`), linked into the workload through
`engine-native`, the crate that owns the C calls. `ENCLAVE_ENGINE_SHA256` is the SHA-256 of that library: the workload
starts only when it equals the hash of the library it was built with, so the pin in the container's environment, and in
the policy, names the engine. The signed result carries `engine` (`native`), `engineVersion` and `engineLibrarySha256`.

Every run has a deadline (`ENCLAVE_ENGINE_DEADLINE_SECS`), checked before each slice of bytes is fed; a watchdog ends the
process when a call into the engine stays open 120 seconds past it. An appraisal's second pass is given half of the
container's memory, at least 256 MiB and at most 1 GiB, for its duplicate counts: a file whose row keys need more is read
once more for each slice, and every result is the same for any budget.

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
