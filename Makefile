ROOT_DIR?=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
OUT?=${ROOT_DIR}/../out/cert-ssh

BASE_DISTROLESS?=gcr.io/distroless/static
BASE_DEBUG?=ubuntu:bionic
DOCKER_REPO?=gcr.io/dmeshgate/sshmesh

export DOCKER_REPO

GOPROXY?=https://proxy.golang.org
export GOPROXY

all: build push/gate push/sshd

build:
	mkdir -p ${OUT}/etc/ssl/certs/
	cp /etc/ssl/certs/ca-certificates.crt ${OUT}/etc/ssl/certs/
	mkdir -p ${OUT}/usr/local/bin
	#CGO_ENABLED=0  GOOS=linux GOARCH=amd64 time
	go build \
		-o ${OUT}/usr/local/bin/ \
		./cmd/min ./cmd/ssh-gate-min ./cmd/sshd ./cmd/ssh-gate-min ./cmd/ssh-signerd-min

	(cd sshca-grpc && CGO_ENABLED=0  GOOS=linux GOARCH=amd64 time  go build \
		-ldflags '-s -w -extldflags "-static"' \
		-o ${OUT}/usr/local/bin/ \
		./sshca-grpc-min ./sshca-grpc-proxyless ./sshca-grpc ./sshca-grpc-cli/ )

	(cd cmd/sshgate && CGO_ENABLED=0  GOOS=linux GOARCH=amd64 time  go build \
		-ldflags '-s -w -extldflags "-static"' \
		-o ${OUT}/usr/local/bin/ \
		. )
	ls -l ${OUT}/usr/local/bin
	strip ${OUT}/usr/local/bin/*
	ls -l ${OUT}/usr/local/bin

ko/build: ko/sshca ko/sshd

docker:
	docker build -t ${DOCKER_REPO}/sshd -f tools/docker/Dockerfile.sshd ${OUT}
	docker build -t ${DOCKER_REPO}/mesh -f tools/docker/Dockerfile.sshmesh ${OUT}

push/docker:
	docker push ${DOCKER_REPO}/sshd
	docker push ${DOCKER_REPO}/gate


_push:
	(export SSHDRAW=$(shell cd ${OUT} && tar -cf - etc ${PUSH_FILES} | \
					  gcrane append -f - -b ${BASE_DISTROLESS} \
						-t ${DOCKER_REPO}/gate-distroless:latest \
					   ) && \
	gcrane mutate $${SSHDRAW} --entrypoint /usr/local/bin/ssh-signerd && \
	gcrane rebase --rebased ${DOCKER_REPO}/gate:latest \
	   --original $${SSHDRAW} \
	   --old_base ${BASE_DISTROLESS} \
	   --new_base ${BASE_DEBUG} \
	)

# Append files to an existing container
push/gate:
	PUSH_FILES=usr/local/bin/ssh-signerd $(MAKE) _push

push/sshd:
	PUSH_FILES=usr/local/bin/sshd $(MAKE) _push


# Use openssh client
ssh/openssh-client:
	ssh -v  -p 15022  \
		-o "UserKnownHostsFile sshca/testdata/known-hosts" \
		-o StrictHostKeyChecking=yes \
		-i sshca/testdata/id_ecdsa \
		localhost env

ssh/keygen:
	rm -rf testdata/keygen
	mkdir -p testdata/keygen
	ssh-keygen -t ecdsa   -f testdata/keygen/id_ecdsa -N ""

ssh/getcert: CRT=$(shell cat testdata/keygen/id_ecdsa.pub)
ssh/getcert:
	echo {\"public\":\"${CRT}\"} | \
 		grpcurl -plaintext  -d @   [::1]:8080 ssh.SSHCertificateService/CreateCertificate | \
 		jq -r .user > testdata/keygen/id_ecdsa-cert.pub

	echo {\"public\":\"${CRT}\"} | \
 		grpcurl -plaintext  -d @   [::1]:8080 ssh.SSHCertificateService/CreateCertificate

ssh/getcert-k8s: CRT=$(shell cat testdata/keygen/id_ecdsa.pub)
ssh/getcert-k8s:
	echo {\"public\":\"${CRT}\"} | \
 		grpcurl -plaintext  -d @   [::1]:14021 ssh.SSHCertificateService/CreateCertificate

deps:
	go install github.com/google/go-containerregistry/cmd/gcrane@latest
