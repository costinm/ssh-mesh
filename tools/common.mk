BASE:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
REPO?=$(shell basename $(BASE))

# Tools directory (this imported makefile, should be in tools/common.mk)
TOOLS:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

# Source dir (same as BASE and ROOT_DIR ?)
SRC_DIR:=$(shell dirname $(TOOLS))

-include ${HOME}/.local.mk
-include ${SRC_DIR}/.local.mk

BUILD_DIR?=/tmp
OUT?=${BUILD_DIR}/${REPO}

# Compiling with go build will link the local machine glibc
# Debian 11 is based on 2.31, testing is 2.36
GOSTATIC=CGO_ENABLED=0  GOOS=linux GOARCH=amd64 time  go build -ldflags '-s -w -extldflags "-static"' -o ${OUT}/

# Requires docker login ghcr.io -u USERNAME -p TOKEN
DOCKER_REPO?=ghcr.io/costinm

BASE_DISTROLESS?=gcr.io/distroless/static
BASE_IMAGE?=debian:testing-slim

# For github:
#DOCKER_REPO?=costinm

GOPROXY?=https://proxy.golang.org

export GOPROXY
export DOCKER_REPO
export PATH:=$(PATH):${HOME}/go/bin

echo:
	@echo BASE: ${BASE}
	@echo SRC_DIR: ${SRC_DIR}
	@echo TOP: ${TOP}
	@echo OUT: ${OUT}
	@echo DOCKER_REPO: ${DOCKER_REPO}
	@echo BASE_DISTROLESS: ${BASE_DISTROLESS}
	@echo REPO: ${REPO}
	@echo MAKEFILE_LIST: $(MAKEFILE_LIST)

TAG?=latest

# TODO: instead of /usr/local/bin, use /app/$APP/bin or something
# easier to mount. Flatpack or other conventions would work.

# Push last layer and set entrypoint for a docker image using crane.
# This is using ${OUT} directory as base.
#
# Params:
# - CMD - the name of the command, should be in  ${OUT}/usr/local/bin
# - PUSH_FILES - extra files from $OUT to add to image
# - DOCKER_REPO - base for the docker, /CMD:tag will be added
# - BASE_IMAGE - where to add the files.
_crane_push:
	env
	(export SSHDRAW=$(shell cd ${OUT} && tar -cf - etc usr/local/bin/${CMD} ${PUSH_FILES} | \
					  gcrane append -f - -b ${BASE_DEBUG} -t ${DOCKER_REPO}/${CMD}:${TAG} ) && \
	gcrane mutate $${SSHDRAW} -t ${DOCKER_REPO}/${CMD}:${TAG} --entrypoint /usr/local/bin/${CMD} \
	)

# Older version, in process of replace
_push:
		(export IMG=$(shell cd ${OUT} && tar -cf - ${PUSH_FILES} ${BIN} | \
    					  gcrane append -f - -b ${BASE_IMAGE} \
    						-t ${DOCKER_REPO}/${BIN}:latest \
    					   ) && \
    	gcrane mutate $${IMG} -t ${DOCKER_REPO}/${BIN}:latest --entrypoint /${BIN} \
    	)

# To create a second image with a different base
#	gcrane rebase --rebased ${DOCKER_REPO}/gate:latest \
#	   --original $${SSHDRAW} \
#	   --old_base ${BASE_DISTROLESS} \
#	   --new_base ${BASE_DEBUG} \

_oci_base:
	gcrane mutate ${OCI_BASE} -t ${DOCKER_REPO}/${BIN}:base --entrypoint /${BIN}

_oci_image:
	(cd ${OUT} && tar -cf - ${PUSH_FILES} ${BIN} | \
    	gcrane append -f - \
    				  -b  ${DOCKER_REPO}/${BIN}:base \
    				  -t ${DOCKER_REPO}/${BIN}:latest )

_oci_local: build
	docker build -t costinm/hbone:latest -f tools/Dockerfile ${OUT}/


.go-build:
	(cd cmd/${NAME} && go build -o ${OUT}/${NAME} .)

deps:
	go install github.com/google/go-containerregistry/cmd/gcrane@latest
