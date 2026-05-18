FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o proxy .

FROM alpine:3.20
# ca-certificates required for TLS connections to WSS brokers
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /app/proxy /proxy
ENTRYPOINT ["/proxy"]
