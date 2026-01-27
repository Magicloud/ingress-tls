# syntax=docker/dockerfile:1.7-labs

FROM ghcr.io/magicloud/rust-stable:latest AS builder

WORKDIR /usr/src/myapp
COPY --exclude=target . .

RUN cargo install --path . --target x86_64-unknown-linux-musl


FROM alpine:latest

RUN adduser -D worker -u 1000
USER 1000

EXPOSE 443/TCP

COPY --from=builder /usr/local/cargo/bin/ingress-tls /usr/local/bin/ingress-tls

ENTRYPOINT ["ingress-tls"]
