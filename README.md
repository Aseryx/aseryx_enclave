# aseryx_enclave

The workload that Aseryx runs inside an AMD SEV-SNP confidential container on Azure Container
Instances. It computes appraisals and threshold answers over a dataset's decrypted bytes without any
operator, Aseryx included, being able to read them.

This repository is public so anyone can inspect the code the owner consents to.

Status: under construction. The first work is a spike that measures the platform.

## Image

The `image` workflow builds the image twice from scratch and fails unless both builds have the same
digest. A manual run with `publish` set copies the verified image to
`ghcr.io/aseryx/aseryx-enclave` under the tag `sha-<first 12 characters of the commit>` and checks
that the registry holds the digest the builds produced. The package is made public in the
repository owner's package settings.

The files' timestamps in the image are the Unix time in `SOURCE_DATE_EPOCH`, a file in the repository
root, not the time of a commit, so the image digest and the policy hash depend only on the build inputs
(`Dockerfile`, `Cargo.toml`, `Cargo.lock`, `harness`, `engine`, `SOURCE_DATE_EPOCH`) and do not change with a
commit, a rebase or a squash merge that leaves them alone.
