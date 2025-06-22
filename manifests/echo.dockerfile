ARG IMAGE=gcr.io/istio-testing/app:latest

# This is an example container including sshm as entrypoint, and multiple
# servers. 
# 
# The base image is one of the servers - Istio echo serve, and the
# second server (fortio) is added.
#
# 


FROM costinm/sshm:latest as sshm
FROM fortio/fortio:latest as fortio

FROM ${IMAGE} as app

COPY --from=sshm /ko-app/sshm /ko-app/sshm
COPY --from=fortio /usr/bin/fortio /usr/bin/fortio
COPY --from=fortio /var/lib/fortio/ /var/lib/fortio/
WORKDIR /var/lib/fortio

ENTRYPOINT ["/ko-app/sshm"]

# start the server mode (grpc ping on 8079, http echo and UI on 8080, redirector on 8081) by default
#CMD ["/usr/local/bin/server"]
CMD ["/usr/bin/fortio", "server", "-config-dir", "/etc/fortio"]
