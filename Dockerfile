FROM golang:latest AS build

#FROM golang:alpine AS build-base
# dlv doesn't seem to work yet ?

WORKDIR /ws
ENV GO111MODULE=on
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOPROXY=https://proxy.golang.org

COPY sshca ./sshca
COPY ssh ./ssh

RUN pwd && cd /ws/sshca && go build -a -gcflags='all=-N -l' -ldflags '-extldflags "-static"' -o /ws/ssh-signerd ./ssh-signerd
RUN pwd && cd /ws/ssh && go build -a -gcflags='all=-N -l' -ldflags '-extldflags "-static"' -o /ws/sshd ./sshd

## Same base as Istio debug
FROM ubuntu:bionic AS sshd
# Or distroless
#FROM docker.io/istio/base:default AS wps

COPY --from=build /ws/sshd /ko-app/sshd

ENV KO_DATA_PATH=/var/run/ko
WORKDIR /
ENTRYPOINT ["/ko-app/sshd"]

FROM ubuntu:bionic AS sshca

COPY --from=build /ws/ssh-signerd /ko-app/ssh-signerd

ENV KO_DATA_PATH=/var/run/ko
WORKDIR /
ENTRYPOINT ["/ko-app/ssh-signerd"]
