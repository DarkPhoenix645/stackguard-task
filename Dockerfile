# Build stage
FROM golang:1.24.6 AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o stackguard-task cmd/server/main.go

# Runtime stage
FROM debian:bookworm-slim AS runner

# Install required runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tzdata \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /root/

COPY --from=builder /app/stackguard-task .
COPY --from=builder /app/web ./web

EXPOSE 8080

CMD ["./stackguard-task"]