FROM golang:1.18 AS build

WORKDIR /usr/src/nexus-oidc-proxy

COPY main.go go.mod go.sum ./

RUN GCO_ENABLED=0 GOOS=linux go build -a -ldflags="-w -extldflags "-static"" -tags netgo main.go

FROM alpine:3.16 AS certs

RUN apk add ca-certificates-bundle

FROM scratch

COPY --from=build /usr/src/nexus-oidc-proxy/main /proxy
COPY --from=certs /etc/ssl/cert.pem /etc/ssl/cert.pem

VOLUME /etc/nexus-oidc-proxy

ENTRYPOINT ["/proxy"]
CMD ["--config", "/etc/nexus-oidc-proxy/nexus-oidc-proxy.cfg"]
