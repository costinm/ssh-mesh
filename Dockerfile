# Build stage using Rust with MUSL for static linking
FROM rust:slim-bookworm AS build

RUN apt-get update && apt-get install -y \
    musl-tools \
    clang \
    curl \
    gcc-aarch64-linux-gnu \
    && rm -rf /var/lib/apt/lists/*

# Utoipa-swagger-ui build depends on curl to download swagger-ui

RUN rustup target add x86_64-unknown-linux-musl
RUN rustup target add aarch64-unknown-linux-musl
WORKDIR /src

# Copy workspace configuration and sources
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build both pmond and ssh-mesh targets for MUSL, built individually
# Less efficient (duplicate builds of common deps), but want to evaluate each
RUN cargo build --target x86_64-unknown-linux-musl --release -p pmond
RUN cargo build --features pmon --target x86_64-unknown-linux-musl --release -p ssh-mesh
RUN CC_aarch64_unknown_linux_musl=aarch64-linux-gnu-gcc CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc \
    cargo build --features pmon --target aarch64-unknown-linux-musl --release -p ssh-mesh

# Build rvirtiofsd statically
RUN RUSTFLAGS="-C target-feature=+crt-static" \
    cargo build --target x86_64-unknown-linux-musl --release -p rvirtiofsd

# -----------------------
FROM rust:slim-bookworm AS build-android

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Download and install Android NDK
ENV ANDROID_NDK_VERSION=r27b
ENV ANDROID_NDK_HOME=/opt/android-ndk
RUN curl -o ndk.zip https://dl.google.com/android/repository/android-ndk-${ANDROID_NDK_VERSION}-linux.zip && \
    unzip -q ndk.zip && \
    rm ndk.zip && \
    mv android-ndk-${ANDROID_NDK_VERSION} ${ANDROID_NDK_HOME}

# Add Rust Android targets
RUN rustup target add aarch64-linux-android
RUN rustup target add x86_64-linux-android

# Set up environment variables for Android NDK toolchains
ENV PATH="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin:${PATH}"
ENV CC_aarch64_linux_android=aarch64-linux-android34-clang
ENV CXX_aarch64_linux_android=aarch64-linux-android34-clang++
ENV AR_aarch64_linux_android=llvm-ar
ENV CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=aarch64-linux-android34-clang
ENV CC_x86_64_linux_android=x86_64-linux-android34-clang
ENV CXX_x86_64_linux_android=x86_64-linux-android34-clang++
ENV AR_x86_64_linux_android=llvm-ar
ENV CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER=x86_64-linux-android34-clang

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build for aarch64-linux-android
RUN cargo build --features pmon --target aarch64-linux-android --release -p ssh-mesh

# Build for x86_64-linux-android
RUN cargo build --features pmon --target x86_64-linux-android --release -p ssh-mesh


# -----------------------
# Use with 
# docker build --progress=plain --output . --target bin .
FROM scratch as bin

COPY --from=build /src/target/x86_64-unknown-linux-musl/release/ssh-mesh .
COPY --from=build /src/target/aarch64-unknown-linux-musl/release/ssh-mesh ssh-mesh.aarch64
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/h2t .
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/meshkeys .
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/pmond .
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/rvirtiofsd .

# ------------------------
# Final stage for creating a test docker image with various utils.
FROM nicolaka/netshoot

# Copy the statically linked binaries from the build stage
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/ssh-mesh /usr/local/bin/ssh-mesh
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/pmond /usr/local/bin/pmond
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/rvirtiofsd /usr/local/bin/rvirtiofsd

# Use ssh-mesh as the default entrypoint
ENTRYPOINT ["/usr/local/bin/ssh-mesh"]
