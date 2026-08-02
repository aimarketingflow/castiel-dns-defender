FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git make

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=docker" -o castiel .

FROM alpine:3.20

RUN apk add --no-cache ca-certificates nftables iptables

COPY --from=builder /build/castiel /usr/local/bin/castiel
COPY --from=builder /build/config.yaml /etc/castiel/config.yaml
COPY --from=builder /build/data /etc/castiel/data

RUN mkdir -p /var/log/castiel

EXPOSE 5300/udp 5300/tcp 9090/tcp

ENTRYPOINT ["castiel", "-config", "/etc/castiel/config.yaml"]
