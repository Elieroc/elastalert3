# syntax=docker/dockerfile:1

# ---- build ----
FROM rust:1-bookworm AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src

# Dependencies first, so source changes don't rebuild them.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
 && cargo build --release --locked \
 && rm -rf src target/release/elastalert target/release/deps/elastalert* target/release/.fingerprint/elastalert*

COPY src ./src
COPY mappings ./mappings
COPY attack ./attack
RUN cargo build --release --locked \
 && strip target/release/elastalert

# ---- runtime ----
# debian-slim rather than distroless: the `command` alerter may run `sh -c`.
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /opt/elastalert --shell /usr/sbin/nologin elastalert \
 && mkdir -p /opt/elastalert/rules \
 && chown -R elastalert /opt/elastalert

COPY --from=build /src/target/release/elastalert /usr/local/bin/elastalert
COPY NOTICE /usr/share/doc/elastalert3/NOTICE

USER elastalert
WORKDIR /opt/elastalert
# config.yaml and rules/ are mounted here; rules_folder is relative to the working directory.
# ES_HOST, ES_PORT, ES_USERNAME, ES_PASSWORD, ES_API_KEY, ES_BEARER, ES_USE_SSL, ES_URL_PREFIX override the config.
ENTRYPOINT ["elastalert"]
CMD ["--config", "/opt/elastalert/config.yaml"]
