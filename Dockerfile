# =========================
# Build stage
# =========================
FROM alpine:3.16 AS builder

# Install Rust and build dependencies
RUN apk update && \
    apk add --no-cache \
      gcc \
      musl-dev \
      openssl-dev \
      pkgconfig \
      curl \
      perl \
      make \
      git \
      linux-headers && \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo \
        sh -s -- --profile minimal --default-toolchain stable -y && \
    rm -rf /root/.cargo/registry /root/.cargo/git

ENV PATH="/usr/local/cargo/bin:${PATH}" \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo

WORKDIR /usr/src/whoop_scraper
COPY Cargo.toml Cargo.lock ./

# Create a dummy src directory to pre-build dependencies
RUN mkdir -p src && \
    echo "fn main() {println!(\"dummy\");}" > src/main.rs && \
    echo "pub mod data_downloader { pub async fn download_whoop_data(_: &str, _: &str) -> anyhow::Result<()> { Ok(()) } }" > src/lib.rs


# Now copy the real source code
COPY src ./src

# Rebuild with actual code
RUN cargo build --release --features nsm && \
    rm -rf target/release/.fingerprint/*/hash* \
           target/release/deps/* \
           target/release/build/*


# =========================
# Runtime stage
# =========================
FROM alpine:3.16

# Install runtime deps + socat + iproute2 for loopback
RUN apk update && \
    apk add --no-cache \
      chromium \
      chromium-chromedriver \
      harfbuzz \
      nss \
      freetype \
      ttf-freefont \
      font-noto-emoji \
      curl \
      ca-certificates \
      socat \
      iproute2 \
      # Added for Nitro SDK support
      #aws-nitro-enclaves-cli \
      #aws-nitro-enclaves-cli-devel \
      # Make sure we have openssl libraries
      openssl-dev && \
    rm -rf /var/cache/apk/*

WORKDIR /usr/src/whoop_scraper

# Copy your built binary and metadata
COPY --from=builder /usr/src/whoop_scraper/target/release/whoop_scraper ./
COPY --from=builder /usr/src/whoop_scraper/Cargo.toml ./
COPY --from=builder /usr/src/whoop_scraper/Cargo.lock ./

# Create downloads dir
RUN mkdir -p /downloads

# Build an entrypoint that only adds the loopback IP if it's missing
RUN echo '#!/bin/sh'                                                  > /entrypoint.sh && \
    echo 'set -e'                                                     >> /entrypoint.sh && \
    echo ''                                                           >> /entrypoint.sh && \
    echo '# 1) Ensure loopback is up (ignore if already up)'          >> /entrypoint.sh && \
    echo 'ip link set lo up || true'                                  >> /entrypoint.sh && \
    echo ''                                                           >> /entrypoint.sh && \
    echo '# 2) Add 127.0.0.1/8 to lo only if missing'                  >> /entrypoint.sh && \
    echo 'if ! ip addr show dev lo | grep -q "127.0.0.1/8"; then'      >> /entrypoint.sh && \
    echo '  ip addr add 127.0.0.1/8 dev lo'                            >> /entrypoint.sh && \
    echo 'fi'                                                         >> /entrypoint.sh && \
    echo ''                                                           >> /entrypoint.sh && \
    echo '# 3) Bridge VSock 8080 → localhost:8080 (Actix API)'        >> /entrypoint.sh && \
    echo 'socat VSOCK-LISTEN:8080,reuseaddr,fork TCP:127.0.0.1:8080 &' >> /entrypoint.sh && \
    echo ''                                                           >> /entrypoint.sh && \
    echo '# 4) Bridge TCP 3128 → VSock 3128 (HTTP proxy)'              >> /entrypoint.sh && \
    echo 'socat TCP-LISTEN:3128,reuseaddr,fork VSOCK-CONNECT:3:3128 &' >> /entrypoint.sh && \
    echo ''                                                           >> /entrypoint.sh && \
    echo '# 5) Exec your Rust HTTP server'                             >> /entrypoint.sh && \
    echo 'RUST_LOG=info exec /usr/src/whoop_scraper/whoop_scraper server --port 8080'>> /entrypoint.sh && \
    chmod +x /entrypoint.sh

# (Optional) declare ports
EXPOSE 8080 8081

# Use our entrypoint
ENTRYPOINT ["/entrypoint.sh"]
