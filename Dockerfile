# fileshare: one static Rust binary (musl) on an empty (scratch) base.
#
# Everything lives in the binary: the HEALTHCHECK client (`fileshare
# healthcheck`) and the startup banner -- with the label below,
# .gitea/scripts/add-banner.sh only adds the rendered banner text, which the
# binary prints on start (there is no shell for the usual wrapper).

FROM rust:1.99-alpine AS build
RUN apk add --no-cache musl-dev \
 && cargo install --locked cargo-auditable@0.7.7
WORKDIR /src
# Dependency layer first: only rebuilt when Cargo.toml/Cargo.lock change.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
 && cargo auditable build --release --locked \
 && cargo test --release --locked --no-run \
 && rm -rf src
COPY src src
# `touch`: the dummy main.rs above is newer than nothing cargo knows about.
# cargo auditable embeds the dependency list in the binary, so Trivy can scan
# the crates of the final image.
# The test suite (unit + HTTP-level incl. MCP auth) gates the image: a
# failing test fails the build, so CI never pushes it.
RUN touch src/main.rs \
 && cargo test --release --locked \
 && cargo auditable build --release --locked \
 && install -D -m 0755 target/release/fileshare /out/fileshare \
 && mkdir -p /out/data

FROM scratch
LABEL de.linux-ng.image-banner=builtin
COPY --from=build /out/fileshare /fileshare
COPY --from=build --chown=1000:1000 /out/data /data
ENV BIND=0.0.0.0:8080 \
    DATA_DIR=/data
USER 1000:1000
VOLUME /data
EXPOSE 8080/tcp
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/fileshare", "healthcheck"]
ENTRYPOINT ["/fileshare"]
