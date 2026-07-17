FROM rust:1.88-slim-bookworm AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add wasm32-unknown-unknown

RUN curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash

RUN cargo binstall cargo-leptos -y
RUN cargo binstall wasm-bindgen-cli@0.2.114 -y

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY crates/server/Cargo.toml   crates/server/Cargo.toml
COPY crates/db/Cargo.toml       crates/db/Cargo.toml
COPY crates/auth/Cargo.toml     crates/auth/Cargo.toml
COPY crates/crypto/Cargo.toml   crates/crypto/Cargo.toml
COPY crates/frontend/Cargo.toml crates/frontend/Cargo.toml

COPY crates/ crates/

COPY .sqlx .sqlx
ENV SQLX_OFFLINE=true

RUN cargo leptos build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/server /app/server

COPY --from=builder /app/target/site /app/site

ENV LEPTOS_SITE_ROOT=/app/site
ENV LEPTOS_SITE_PKG_DIR=pkg
ENV LEPTOS_OUTPUT_NAME=frontend
ENV LEPTOS_SITE_ADDR=0.0.0.0:8080

EXPOSE 8080

ENTRYPOINT ["/app/server"]
