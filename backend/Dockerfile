# syntax=docker/dockerfile:1

FROM golang:1.21-bullseye AS builder

WORKDIR /app
ENV GOPROXY=https://goproxy.cn,direct

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /app/bin/server ./cmd/server && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /app/bin/init-admin ./cmd/init-admin

FROM debian:bookworm-slim

ENV TZ=Etc/UTC \
    CHROME_BIN=/usr/bin/chromium

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        chromium \
        dumb-init \
        fonts-dejavu-core \
        nmap \
        python3 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --home /app --shell /usr/sbin/nologin appuser

WORKDIR /app

COPY --from=builder /app/bin/server /app/arl-vp3
COPY --from=builder /app/bin/init-admin /app/init-admin
COPY configs /app/configs
COPY web /app/web

RUN cp /app/configs/config.docker.yaml /app/configs/config.yaml && \
    mkdir -p /app/data/screenshots /app/data/exports /app/logs && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 5003

ENTRYPOINT ["/usr/bin/dumb-init","--"]
CMD ["/app/arl-vp3"]
