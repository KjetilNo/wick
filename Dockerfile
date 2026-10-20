# syntax=docker/dockerfile:1

FROM rust:1-slim-bookworm AS builder
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Cache dependency compilation separately from application code.
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo "fn main() {}" > src/main.rs \
    && cargo build --release \
    && rm -rf src

COPY src ./src
COPY templates ./templates
COPY static ./static
COPY migrations ./migrations
# Touch main.rs so the dummy build above doesn't get reused for the real binary.
RUN touch src/main.rs && cargo build --release

FROM debian:bookworm-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 wick

COPY --from=builder /app/target/release/wick /usr/local/bin/wick

ENV PORT=8080 \
    DATABASE_URL=sqlite:/data/secrets.db \
    RUST_LOG=wick=info,tower_http=info

RUN mkdir -p /data && chown wick:wick /data
USER wick

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/wick"]
