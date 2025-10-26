# The build targets allow to build the binary and container image
.PHONY: build

-include ${HOME}/.env.mk

BINARY        ?= sshm
REGISTRY      ?= costinm
REPO_IMAGE         ?= $(REGISTRY)/$(BINARY)

# Ko provides this env
IMAGE_TAG ?= latest

VERSION       ?= $(shell git describe --tags --always --dirty --match "v*")
IMG_PUSH      ?= true
IMG_SBOM      ?= none

PROJECT_ID?=dmeshgate
REGION?=us-central1
GCLOUD_USER=$(shell gcloud config get-value account)
#GSA="dns-sync@${GKE_PROJECT_ID}.iam.gserviceaccount.com"

GO_HOME ?= ${HOME}/go

mod:
	go mod tidy
	go build -buildmode=c-shared  ./cmd/sshm

plugin:
	go mod tidy
	go build -buildmode=plugin -o $(BINARY)_plugin.so ./cmd/sshm

# Build ssh-mesh using ko
# Simpler:	KO_DOCKER_REPO=costinm ko build --tags latest --sbom none -B --push=true cmd/sshm
pushx:
	@echo Context: ${BUILD_CONTEXT}
	@echo Image: ${REPO_IMAGE}
	@echo Tag: ${IMAGE_TAG}
	@echo Go: ${GO_HOME}
	KO_DOCKER_REPO=${REGISTRY} \
		 VERSION=${VERSION} \
       ${GO_HOME}/bin/ko build --tags ${IMAGE_TAG} -B --sbom ${IMG_SBOM} \
		  --image-label org.opencontainers.image.source="https://github.com/costinm/ssh-mesh" \
		  --image-label org.opencontainers.image.revision=$(shell git rev-parse HEAD) \
		   --push=${IMG_PUSH} ./cmd/sshm

deps:
	#go install github.com/google/ko@v0.17.1
	go install github.com/google/ko@latest
