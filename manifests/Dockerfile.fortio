FROM fortio/fortio:latest as fortio

FROM costinm/sshc:latest

COPY --from=fortio /usr/bin/fortio /usr/bin/fortio
COPY --from=fortio /usr/bin/fortio /usr/bin/fortio
COPY --from=fortio /usr/bin/fortio /usr/bin/fortio

WORKDIR /var/lib/fortio
ENTRYPOINT ["/sshc"]
# start the server mode (grpc ping on 8079, http echo and UI on 8080, redirector on 8081) by default
CMD ["/usr/bin/fortio", "server", "-config-dir", "/etc/fortio"]