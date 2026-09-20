# Build static Linux binaries for the standalone container image. Android
# artifacts belong to the DMesh build and are intentionally not built here.
FROM rust:slim-bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    musl-tools \
    && rm -rf /var/lib/apt/lists/*
RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build the packages that provide the runtime binaries in one
# dependency-sharing invocation.
RUN cargo build --target x86_64-unknown-linux-musl --release \
    -p mesh-init -p mesh-cli -p ssh-mesh

# Assemble a stable /opt layout once so the scratch and diagnostic images use
# identical binaries and canonical mesh-init defaults.
FROM scratch AS runtime-root
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/mesh-init /opt/ssh-mesh/bin/mesh-init
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/ssh-mesh /opt/ssh-mesh/bin/ssh-mesh
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/mesh /opt/ssh-mesh/bin/mesh
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/h2t /opt/ssh-mesh/bin/h2t
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/meshkeys /opt/ssh-mesh/bin/meshkeys
COPY crates/mesh-init/defaults /opt/ssh-mesh/share/mesh-init/defaults

# This is mutable container state. It begins with the canonical default, and
# mesh-init preserves any later operator edit instead of overwriting it.
COPY crates/mesh-init/defaults/ssh-mesh.toml /home/system/etc/mesh-init/ssh-mesh.toml

FROM runtime-root AS scratch
ENV PATH=/opt/ssh-mesh/bin
EXPOSE 15022 8080
ENTRYPOINT ["/opt/ssh-mesh/bin/mesh-init"]

# A diagnostics-friendly variant for ordinary Docker/Podman use. It has the
# same rootfs payload and supervisor entrypoint as the scratch target.
FROM nicolaka/netshoot AS netshoot
COPY --from=runtime-root /opt /opt
COPY --from=runtime-root /home /home
ENV PATH=/opt/ssh-mesh/bin:${PATH}
EXPOSE 15022 8080
ENTRYPOINT ["/opt/ssh-mesh/bin/mesh-init"]
