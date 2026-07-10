# ─── Stage 1: Build ───────────────────────────────────────────────────────────
FROM rust:1.88-slim-bookworm AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Add WASM compilation target
RUN rustup target add wasm32-unknown-unknown

# Install cargo-binstall (pulls pre-built binaries incredibly fast)
RUN curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash

# Install cargo-leptos and matching wasm-bindgen-cli using binaries
RUN cargo binstall cargo-leptos -y
RUN cargo binstall wasm-bindgen-cli@0.2.114 -y

WORKDIR /app

# Copy workspace manifests first for better layer caching
COPY Cargo.toml Cargo.lock ./
COPY crates/server/Cargo.toml   crates/server/Cargo.toml
COPY crates/db/Cargo.toml       crates/db/Cargo.toml
COPY crates/auth/Cargo.toml     crates/auth/Cargo.toml
COPY crates/crypto/Cargo.toml   crates/crypto/Cargo.toml
COPY crates/frontend/Cargo.toml crates/frontend/Cargo.toml

# Copy all source code
COPY crates/ crates/

# sqlx offline query cache (generated with `cargo sqlx prepare --workspace`)
# lets query! macros compile without a live database
COPY .sqlx .sqlx
ENV SQLX_OFFLINE=true

# Build the full stack (server binary + WASM frontend)
RUN cargo leptos build --release

# ─── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the server binary
COPY --from=builder /app/target/release/server /app/server

# Copy the frontend assets built by cargo-leptos (WASM + JS + CSS)
COPY --from=builder /app/target/site /app/site

# Leptos runtime configuration
ENV LEPTOS_SITE_ROOT=/app/site
ENV LEPTOS_SITE_PKG_DIR=pkg
ENV LEPTOS_OUTPUT_NAME=frontend
ENV LEPTOS_SITE_ADDR=0.0.0.0:8080

EXPOSE 8080

ENTRYPOINT ["/app/server"]
