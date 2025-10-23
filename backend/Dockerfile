# syntax=docker/dockerfile:1

FROM golang:1.24-bullseye AS builder

# 1. Install libpcap-dev for CGO to link against
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpcap-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
ENV GOPROXY=https://goproxy.cn,direct

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# 2. Remove CGO_ENABLED=0 so Go can link with libpcap
# RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /app/bin/server ./cmd/server && \
#     CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /app/bin/init-admin ./cmd/init-admin
RUN GOOS=linux GOARCH=amd64 go build -o /app/bin/server ./cmd/server && \
    GOOS=linux GOARCH=amd64 go build -o /app/bin/init-admin ./cmd/init-admin
    # Note: We keep the GOOS/GOARCH flags for cross-compilation environment consistency

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
# 3. Important: libpcap is required at runtime for the binary
        libpcap0.8 \
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
