# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.26.11-bookworm AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/guardrails-webhook ./cmd/guardrails-webhook

# Static, distroless, non-root (UID 65532), no shell.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/guardrails-webhook /guardrails-webhook
USER 65532:65532
ENTRYPOINT ["/guardrails-webhook"]
