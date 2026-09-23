# Packages an already-built `monitor` binary; it compiles nothing itself.
# The release workflow (.github/workflows/release.yml) lays the published
# release binaries out as dist/docker/<os>/<arch>[/<variant>]/monitor - the
# same shape as Docker's TARGETPLATFORM, e.g. linux/arm/v7 - so the image is
# byte-for-byte the checksummed artifact attached to the GitHub release.
#
# Local build (amd64) after `go build -o dist/docker/linux/amd64/monitor
# ./cmd/monitor` with CGO_ENABLED=0 GOOS=linux GOARCH=amd64:
#
#   docker build -t tenpm-uptime-monitor .
#
# No RUN in the final stage: every RUN in a foreign-architecture stage needs
# QEMU emulation on the build host, and the release job deliberately avoids
# third-party actions (QEMU setup included). The prep stage runs on the
# build host's own platform and only produces plain files to copy.

FROM --platform=$BUILDPLATFORM alpine:3.20 AS prep
# uid/gid pinned (rather than whatever `adduser -S` picks) so a /data volume
# stays writable by the agent across image versions.
RUN addgroup -S -g 101 monitor && \
    adduser -S -u 100 -G monitor -h /data -H monitor && \
    mkdir -p /data && chown 100:101 /data

FROM alpine:3.20
# Filled in by BuildKit per platform. Deliberately no default: a default here
# overrides the automatic value, and every platform would get the same binary.
ARG TARGETPLATFORM
# alpine:3.20 already ships ca-certificates-bundle, which is all the agent's
# TLS needs.
COPY --from=prep /etc/passwd /etc/group /etc/
COPY --from=prep --chown=100:101 /data /data
COPY --chmod=755 dist/docker/${TARGETPLATFORM}/monitor /usr/local/bin/monitor
USER monitor
WORKDIR /data
VOLUME /data

# The SQLite database holds this monitor's identity (the id and API key issued
# at enrollment), so it lives on the /data volume: recreating the container
# with the same volume resumes the same monitor rather than enrolling a new
# one. If the server forgets this monitor (its enrollment is reset), the agent
# keeps presenting the old key and logs 401s - remove /data/monitor.db* and
# restart with a live ENROLLMENT_TOKEN.
ENV DB_PATH=/data/monitor.db

ENTRYPOINT ["/usr/local/bin/monitor"]
