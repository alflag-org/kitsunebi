FROM node:22-bookworm-slim AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web ./
RUN npm run check && npm run test && npm run build

FROM rust:1.88-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --bin kitsunebi-controller --features local-auth -p kitsunebi-controller

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install --no-install-recommends --yes ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 10001 kitsunebi \
    && install -d -o kitsunebi -g kitsunebi /var/lib/kitsunebi/artifacts
COPY --from=build /src/target/release/kitsunebi-controller /usr/local/bin/kitsunebi-controller
COPY --from=web /web/build /var/lib/kitsunebi/web
USER kitsunebi
ENTRYPOINT ["/usr/local/bin/kitsunebi-controller"]
