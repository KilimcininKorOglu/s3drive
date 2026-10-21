# syntax=docker/dockerfile:1

FROM golang:1.27-alpine AS build

ARG VERSION=0.1.0
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags="-s -w -X s3drive/internal/config.Version=${VERSION}" \
    -o /out/s3drive ./cmd/s3drive

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -g 10001 s3drive \
    && adduser -D -H -u 10001 -G s3drive s3drive \
    && mkdir -p /data \
    && chown s3drive:s3drive /data

COPY --from=build /out/s3drive /usr/local/bin/s3drive

USER s3drive
WORKDIR /data

ENV S3DRIVE_DATA_DIR=/data \
    S3DRIVE_S3_ADDR=:9000 \
    S3DRIVE_UI_ADDR=:8080 \
    S3DRIVE_LOG_LEVEL=info

EXPOSE 9000 8080
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/s3drive"]
