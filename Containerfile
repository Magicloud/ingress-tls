# syntax=docker/dockerfile:1.7-labs

FROM ghcr.io/magicloud/rust-stable:latest AS builder

COPY step.crt /usr/local/share/ca-certificates
RUN update-ca-certificates && apk add --no-cache openssl-dev openssl-libs-static && cargo install sccache --force --no-default-features --features=s3

WORKDIR /usr/src/myapp
COPY --exclude=target . .

ENV SCCACHE_BUCKET="sccache"
ENV SCCACHE_REGION="auto"
ENV SCCACHE_ENDPOINT="minio.magicloud.lan:443"
ENV SCCACHE_S3_ENABLE_VIRTUAL_HOST_STYLE="false"
ENV SCCACHE_S3_USE_SSL="false"
ENV SCCACHE_S3_SERVER_SIDE_ENCRYPTION="false"
ENV AWS_ACCESS_KEY_ID="sccache"
ENV AWS_SECRET_ACCESS_KEY="sccache123"

RUN cargo install --path . --target x86_64-unknown-linux-musl


FROM alpine:latest

RUN adduser -D worker -u 1000
USER 1000

EXPOSE 443/TCP

COPY --from=builder /usr/local/cargo/bin/ingress-tls /usr/local/bin/ingress-tls

ENTRYPOINT ["ingress-tls"]
