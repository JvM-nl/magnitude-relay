# Magnitude Relay in a container.
#
#   docker build -t magnitude-relay .
#   docker run -d -p 127.0.0.1:7777:7777 -v relay-data:/data magnitude-relay
#
# or `docker compose up -d` with compose.yaml beside this file. Events live in
# /data; settings are /etc/magnitude-relay/relay.toml, the fully commented file
# `magnitude-relay init` writes, with `bind` opened up so the relay can be
# reached from outside the container. Mount your own file over it to change
# anything (keep `bind = "0.0.0.0:7777"` in it).

ARG RUST_VERSION=1.97.1
ARG DEBIAN_RELEASE=trixie

FROM rust:${RUST_VERSION}-slim-${DEBIAN_RELEASE} AS build
WORKDIR /src
COPY . .
# The registry and target caches survive between builds (BuildKit), so a
# rebuild after a small change takes seconds, not a full fat-LTO build of
# every dependency. The binary is copied out because a cache mount is not
# part of the image.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p relay-server \
    && cp target/release/magnitude-relay /usr/local/bin/magnitude-relay
# The shipped settings: every default, documented, except `bind`. The relay's
# default (127.0.0.1) would only answer inside the container. If the `init`
# template's bind line ever changes, the build stops with an error, so a
# container whose relay can't be reached never gets shipped out.
RUN magnitude-relay init /relay.toml \
    && grep -qx '# bind = "127.0.0.1:7777"' /relay.toml \
    && sed -i 's|^# bind = "127.0.0.1:7777"$|bind = "0.0.0.0:7777"|' /relay.toml

FROM debian:${DEBIAN_RELEASE}-slim
# No ca-certificates: the relay's TLS roots (wss:// [[sync]], Let's Encrypt)
# are compiled in from webpki-roots, so the system store is never read.
RUN groupadd --system --gid 10001 magnitude-relay \
    && useradd --system --uid 10001 --gid 10001 --home-dir /data --no-create-home magnitude-relay \
    && install -d -o magnitude-relay -g magnitude-relay -m 0700 /data
COPY --from=build /usr/local/bin/magnitude-relay /usr/local/bin/magnitude-relay
COPY --from=build /relay.toml /etc/magnitude-relay/relay.toml

USER magnitude-relay
WORKDIR /data
VOLUME /data
EXPOSE 7777

# /live answers 200 once the relay is serving. No curl in the image: bash's
# /dev/tcp is enough for one plain HTTP request to ourselves.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/7777 && printf 'GET /live HTTP/1.0\\r\\n\\r\\n' >&3 && head -n1 <&3 | grep -q ' 200 '"]

# Every command takes the same settings and data, so `docker run ... import -`
# or `docker compose exec relay magnitude-relay ... count` work the same way;
# `--data` beats [store] data, so a mounted relay.toml cannot move the store
# out of the volume by mistake.
ENTRYPOINT ["magnitude-relay", "--config", "/etc/magnitude-relay/relay.toml", "--data", "/data"]
CMD ["serve"]
