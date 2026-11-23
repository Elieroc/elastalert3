# syntax=docker/dockerfile:1

# The daemon image to take the `elastalert` binary from. Build it first from the repository root:  docker build -t elastalert3 .
ARG ELASTALERT_IMAGE=elastalert3:latest

# ---- build ----
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
 && cargo build --release \
 && rm -rf src target/release/elastalert-api target/release/deps/elastalert_api*
COPY src ./src
# the copied sources can be older than the dummy build: force the rebuild
RUN touch src/main.rs && cargo build --release && strip target/release/elastalert-api

# ---- the daemon's binary (validation, test runs, Sigma conversion) ----
FROM ${ELASTALERT_IMAGE} AS daemon

# ---- runtime ----
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /opt/elastalert --shell /usr/sbin/nologin elastalert \
 && mkdir -p /opt/elastalert/rules \
 && chown -R elastalert /opt/elastalert
COPY --from=build /src/target/release/elastalert-api /usr/local/bin/
COPY --from=daemon /usr/local/bin/elastalert /usr/local/bin/

USER elastalert
WORKDIR /opt/elastalert
# Mount the same config.yaml and rules/ as the daemon (rules/ read-write).
# Required: API_READ_TOKEN, API_WRITE_TOKEN (>= 16 chars, different). ES_URL, ES_USERNAME/ES_PASSWORD | ES_API_KEY | ES_BEARER, ES_INSECURE.
EXPOSE 8080
ENTRYPOINT ["elastalert-api"]
