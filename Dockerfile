FROM rust:1.94.1-slim-trixie AS builder

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y \
        --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src
RUN cargo build --locked --release \
    && strip target/release/immortal

FROM debian:13-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y \
        --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --user-group --no-create-home \
        --home-dir /nonexistent --shell /usr/sbin/nologin immortal
COPY --from=builder --chown=immortal:immortal \
    /build/target/release/immortal /usr/local/bin/immortal

USER 10001:10001
ENV IMMORTAL_BIND_ADDR=0.0.0.0 \
    IMMORTAL_PORT=8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/immortal"]
