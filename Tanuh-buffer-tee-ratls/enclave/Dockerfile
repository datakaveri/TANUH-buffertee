FROM golang:1.26-bookworm AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" \
    -o /out/buffer-tee ./cmd/buffer-tee

FROM gcr.io/distroless/static-debian12

COPY --from=build /out/buffer-tee /buffer-tee
COPY certs/tls.crt /certs/tls.crt
COPY certs/tls.key /certs/tls.key

# Declare which env vars the CS operator is allowed to override via tee-env-* metadata.
LABEL "tee.launch_policy.allow_env_override"="RATLS_AUDIENCE,TLS_CERT,TLS_KEY"

EXPOSE 8443
ENTRYPOINT ["/buffer-tee"]
