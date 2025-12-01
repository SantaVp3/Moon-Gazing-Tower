FROM golang:1.24-alpine AS builder
WORKDIR /src

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go env -w GOPROXY=https://proxy.golang.org,direct
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o server .

FROM alpine:latest
RUN apk add --no-cache ca-certificates
WORKDIR /app

COPY --from=builder /src/server /app/server
COPY config /app/config
COPY web /app/web
COPY tools /app/tools

EXPOSE 8080
CMD ["/app/server"]
