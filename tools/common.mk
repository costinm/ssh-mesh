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
GOSTATIC=CGO_ENABLED=0  GOOS=linux GOARCH=amd64 go build -ldflags '-s -w -extldflags "-static"'

# Requires docker login ghcr.io -u vi USERNAME -p TOKEN
GIT_REPO?=${REPO}

# Skaffold can pass this
# When running pods, label skaffold.dev/run-id is set and used for log watching
IMAGE_TAG?=latest

DOCKER_REPO?=ghcr.io/costinm/${GIT_REPO}

BASE_DISTROLESS?=gcr.io/distroless/static
BASE_IMAGE?=debian:testing-slim


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
	# When running in a skafold environment
	# https://skaffold.dev/docs/builders/builder-types/custom/#contract-between-skaffold-and-custom-build-script
	# BUILD_CONTEXT=/x/sync/dmesh-src/ugate-ws/meshauth
    # IMAGE=ghcr.io/costinm/meshauth/meshauth-agent:0cc2116-dirty
    # PUSH_IMAGE=true
    # SKIP_TEST, PLATFORMS
    #
	# Not documented:
	#  IMAGE_TAG=0cc2116-dirty
    #  INVOCATION_ID=92f7287ba5a443f0872b11ace7c82ef2
    # SKAFFOLD_USER=intellij
    # SKAFFOLD_INTERACTIVE=false
    # LOGNAME=costin
    # IMAGE_REPO=ghcr.io/costinm/meshauth/meshauth-agent
	#
	#
    # When running in cluster, https://skaffold.dev/docs/builders/builder-types/custom/#custom-build-script-in-cluster
    # KUBECONTEXT
    # NAMESPACE
    #

# 1. Create a tar file with the desired files (BIN, PUSH_FILES)
# 2. Send it as DOCKER_REPO/BIN:latest - using BASE_IMAGE as base
# 3. Save the SHA-based result as IMG
# 4. Set /BIN as entrypoint and tag again
_push: IMAGE?=${DOCKER_REPO}/${BIN}:${IMAGE_TAG}
_push:
	echo ${IMAGE}
	(export IMG=$(shell cd ${OUT} && tar -cf - ${PUSH_FILES} ${BIN} | \
    					  gcrane append -f - -b ${BASE_IMAGE} \
					 			-t ${IMAGE} \
    					   ) && \
    	gcrane mutate $${IMG} -t ${IMAGE} -l org.opencontainers.image.source="https://github.com/costinm/${GIT_REPO}" --entrypoint /${BIN} \
    	)



# To create a second image with a different base without uploading the tar again:
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
    				  -t ${DOCKER_REPO}/${BIN}:${IMAGE_TAG} )

_oci_local: build
	docker build -t costinm/hbone:${IMAGE_TAG} -f tools/Dockerfile ${OUT}/


.go-build:
	(cd cmd/${NAME} && go build -o ${OUT}/${NAME} .)

deps:
	go install github.com/google/go-containerregistry/cmd/gcrane@latest

_cloudrun:
	gcloud alpha run services replace ${MANIFEST} \
		  --platform managed --project ${PROJECT_ID} --region ${REGION}
