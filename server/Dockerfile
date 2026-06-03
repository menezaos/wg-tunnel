FROM golang:1.21-alpine AS builder
WORKDIR /src
COPY go.mod .
RUN go mod download
COPY *.go .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o wgtunnel .

FROM alpine:3.19
RUN apk add --no-cache wireguard-tools iptables iproute2 && \
    mkdir -p /data /etc/wireguard
COPY --from=builder /src/wgtunnel /usr/local/bin/wgtunnel
COPY web /app/web
WORKDIR /app
EXPOSE 8080
ENTRYPOINT ["wgtunnel"]
