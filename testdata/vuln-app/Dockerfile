FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -o app .

FROM alpine:3.19
COPY --from=builder /src/app /app
EXPOSE 8080
USER nobody
ENTRYPOINT ["/app"]
