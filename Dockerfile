# Build stage using Rust with MUSL for static linking
FROM rust:slim-bookworm AS build

RUN apt-get update && apt-get install -y \
    musl-tools \
    gcc \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /src
COPY . .

# Build both pmond and ssh-mesh targets for MUSL
RUN CC_x86_64_unknown_linux_musl=gcc cargo build --target x86_64-unknown-linux-musl --release -p ssh-mesh
RUN CC_x86_64_unknown_linux_musl=gcc cargo build --target x86_64-unknown-linux-musl --release -p pmond

# Final stage
FROM nicolaka/netshoot

# Copy the statically linked binaries from the build stage
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/ssh-mesh /usr/local/bin/ssh-mesh
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/pmond /usr/local/bin/pmond

# Use ssh-mesh as the default entrypoint
ENTRYPOINT ["/usr/local/bin/ssh-mesh"]
