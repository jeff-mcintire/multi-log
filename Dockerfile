# Builds the three Go services into one small image; compose picks the binary
# per service via `command:`.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/gateway ./cmd/gateway \
 && CGO_ENABLED=0 go build -o /out/controlplane ./cmd/controlplane \
 && CGO_ENABLED=0 go build -o /out/queryproxy ./cmd/queryproxy \
 && CGO_ENABLED=0 go build -o /out/anchorer ./cmd/anchorer \
 && CGO_ENABLED=0 go build -o /out/verifier ./cmd/verifier

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/ /usr/local/bin/
# Default to the gateway; each service overrides this via `command:` in compose.
# Use CMD (not ENTRYPOINT) so the override replaces it entirely.
CMD ["/usr/local/bin/gateway"]
