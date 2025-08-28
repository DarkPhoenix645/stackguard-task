FROM golang:1.24.6-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
# RUN apk add git
RUN GO111MODULE=on GOPROXY=https://goproxy.cn,direct go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o stackguard-task cmd/server/main.go

FROM alpine:latest AS runner
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /root/

COPY --from=builder /app/stackguard-task .
COPY --from=builder /app/web ./web
COPY --from=builder /app/.env .

EXPOSE 8080

CMD ["./stackguard-task"]