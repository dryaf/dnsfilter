# dryaf/deploy supplies the statically linked Linux binary in the build context.
# For a local image, use make container-build.
# Debian 13, nonroot variant; pin the exact multi-architecture image index.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99

LABEL org.opencontainers.image.title="dnsfilter" \
      org.opencontainers.image.source="https://github.com/dryaf/dnsfilter"

COPY --chmod=0555 dns-filter /dns-filter

USER 65532:65532
EXPOSE 53/udp 53/tcp
STOPSIGNAL SIGTERM

# The configuration is mounted separately; the image includes CA certificates
# for HTTPS/TLS upstreams. Use an exec-form command because there is no shell.
CMD ["/dns-filter", "-configFile", "/etc/dnsfilter.yml"]
