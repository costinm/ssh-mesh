ARG IMAGE=gcr.io/istio-testing/app:latest

FROM costinm/sshc:latest as sshm

FROM ${IMAGE} as app

COPY --from=sshm /sshm /sshm

ENTRYPOINT ["/sshm"]

# start the server mode (grpc ping on 8079, http echo and UI on 8080, redirector on 8081) by default
CMD ["/usr/local/bin/server"]