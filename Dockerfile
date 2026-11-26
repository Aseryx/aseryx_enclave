# The workload image. Every input is pinned: the builder and the base by digest, the crates by Cargo.lock, the engine
# module by SHA-256. Built twice from one commit it gives one image digest (see .github/workflows/image.yml).

FROM rust:1.97.1-slim-bookworm@sha256:2775a09d208ff0d7c1f50490c45b62db929e87ba1dcbc3f2132ac71a704bcdd3 AS build

WORKDIR /src
COPY engine engine
RUN cd engine && sha256sum --check --strict aseryx_engine_wasm_bg.wasm.sha256

COPY Cargo.toml Cargo.lock ./
COPY harness harness

# Paths are remapped so the binary does not depend on where the build ran.
ENV RUSTFLAGS="--remap-path-prefix=/src=/build --remap-path-prefix=/usr/local/cargo=/cargo --remap-path-prefix=/usr/local/rustup=/rustup"
ENV CARGO_INCREMENTAL=0
RUN cargo build --release --locked -p aseryx-enclave-harness --bin aseryx-enclave

RUN mkdir -p /rootfs/var/lib/enclave/cache /rootfs/opt/enclave \
 && cp target/release/aseryx-enclave /rootfs/aseryx-enclave \
 && cp engine/aseryx_engine_wasm_bg.wasm /rootfs/opt/enclave/engine.wasm

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f

COPY --from=build --chown=65532:65532 /rootfs/var/lib/enclave /var/lib/enclave
COPY --from=build /rootfs/opt/enclave /opt/enclave
COPY --from=build /rootfs/aseryx-enclave /usr/local/bin/aseryx-enclave

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/aseryx-enclave"]
