# Build stage using Rust with MUSL for static linking
FROM rust:slim-bookworm AS build

RUN apt-get update && apt-get install -y \
    musl-tools \
    gcc \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /src
#COPY . .
COPY crates .

# Build both pmond and ssh-mesh targets for MUSL, built individually
# Less efficient (duplicate builds of common deps), but want to evaluate each
RUN cd pmond && CC_x86_64_unknown_linux_musl=gcc cargo build --target x86_64-unknown-linux-musl --release 
RUN cd ssh-mesh &&  CC_x86_64_unknown_linux_musl=gcc cargo build --target x86_64-unknown-linux-musl --release
#RUN CC_x86_64_unknown_linux_musl=gcc cargo build --target x86_64-unknown-linux-musl --release -p ssh-mesh
#RUN CC_x86_64_unknown_linux_musl=gcc cargo build --target x86_64-unknown-linux-musl --release -p pmond

#RUN ls -lR /src/pmond/target

# -----------------------
# Use with 
# docker build --progress=plain --output . --target bin .
FROM scratch as bin

COPY --from=build /src/ssh-mesh/target/x86_64-unknown-linux-musl/release/ssh-mesh .
COPY --from=build /src/ssh-mesh/target/x86_64-unknown-linux-musl/release/h2t .
COPY --from=build /src/ssh-mesh/target/x86_64-unknown-linux-musl/release/meshkeys .
COPY --from=build /src/pmond/target/x86_64-unknown-linux-musl/release/pmond .

# ------------------------
# Final stage for creating a test docker image with various utils.
FROM nicolaka/netshoot

# Copy the statically linked binaries from the build stage
COPY --from=build /src/ssh-mesh/target/x86_64-unknown-linux-musl/release/ssh-mesh /usr/local/bin/ssh-mesh
COPY --from=build /src/pmond/target/x86_64-unknown-linux-musl/release/pmond /usr/local/bin/pmond

# Use ssh-mesh as the default entrypoint
ENTRYPOINT ["/usr/local/bin/ssh-mesh"]
