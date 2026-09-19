# Dockerfile — runtime image for hostage
# Use this to run hostage in CI / containers without installing Go.
#
#   docker build -t hostage .
#   docker run --rm -v "$PWD:/data" hostage @/data/subs.txt
#
FROM golang:1.22-alpine AS builder

WORKDIR /src
RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=docker" -o /out/hostage .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates bind-tools jq
COPY --from=builder /out/hostage /usr/local/bin/hostage
ENTRYPOINT ["hostage"]
