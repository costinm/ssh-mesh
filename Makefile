include tools/common.mk

#ROOT_DIR?=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
#OUT?=${ROOT_DIR}/../out/cert-ssh


# Base image -
BASE_DEBUG?=ubuntu:bionic

REGION?=us-central1

# Where to push
# For github:
DOCKER_REPO?=ghcr.io/costinm/ssh-mesh
#DOCKER_REPO?=costinm
export DOCKER_REPO

GOPROXY?=https://proxy.golang.org
export GOPROXY

all: build push/gate push/sshd

build: CMD=sshc
build: _build

build/sshd: CMD=sshd
build/sshd: _build

# Expected sizes:
# v1:
# - sshc 9.8M->6.6M
# - sshd + h2c: 10.3/6.9

# Build a command under cmd/CMD
# Params:
# - CMD
#
_build:
	mkdir -p ${OUT}/etc/ssl/certs/
	cp /etc/ssl/certs/ca-certificates.crt ${OUT}/etc/ssl/certs/
	mkdir -p ${OUT}/usr/local/bin
	cd cmd/${CMD} && CGO_ENABLED=0  GOOS=linux GOARCH=amd64 go build \
		-o ${OUT}/usr/local/bin/ .
	ls -l ${OUT}/usr/local/bin/${CMD}
	strip ${OUT}/usr/local/bin/${CMD}
	ls -l ${OUT}/usr/local/bin/${CMD}




# Append files to an existing container
push/sshc:
	CMD=sshc $(MAKE) _crane_push

push/sshd:
	CMD=sshd $(MAKE) _crane_push

# Push to a GCR repo for CR
# Using artifact registry - 0.5G free, 0.10/G after

#gcp/push: DOCKER_REPO=us-central1-docker.pkg.dev/${PROJECT_ID}/sshmesh

push: build push/sshc

all/sshd: build/sshd push/sshd

# Replace the CR service
cr/replace:
	cat manifests/cloudrun.yaml | \
	DEPLOY="$(shell date +%H%M)" envsubst | \
     gcloud alpha run services replace -

# Build, push to gcr.io, update the cloudrun service
# Cloudrun requires gcr or artifact registry
cr: DOCKER_REPO=gcr.io/${PROJECT_ID}/sshmesh
cr: all/sshd cr/replace

crauth:
	gcloud run services add-iam-policy-binding  --region ${REGION} sshc  \
      --member="user:${GCLOUD_USER}" \
      --role='roles/run.invoker'
	gcloud run services add-iam-policy-binding  --region ${REGION} sshc  \
      --member="allUsers" \
      --role='roles/run.invoker'


CR_URL?=$(shell gcloud run services --project ${PROJECT_ID} --region ${REGION} describe ${SERVICE} --format="value(status.address.url)")

cr/info:
cr/info:
	curl -v -H"Authorization: Bearer $(shell gcloud auth print-identity-token)"  --output - ${CR_URL}/

cr/key:
	curl -v -H"Authorization: Bearer $(shell gcloud auth print-identity-token)"  --output - ${CR_URL}/_ssh/key



cr/wait:
	curl -v -H"Authorization: Bearer $(shell gcloud auth print-identity-token)"  --output - ${CR_URL}/wait

cr/echo:
	curl -v -H"Authorization: Bearer $(shell gcloud auth print-identity-token)"  -H "Content-Type: application/octet-stream" --data-binary @/dev/stdin  --output - ${CR_URL}/echo

crssh:
	ssh -o StrictHostKeyChecking=no  -J localhost:2222 sshc.${SSHD} -v

# SSH to the CR service using a h2 tunnel.
# Works if sshd is handling the h2 port, may forward to the app.
# Useful if scaled to zero
pcrssh:
	ssh -o ProxyCommand="${HOME}/go/bin/h2t ${CR_URL}_ssh/tun" \
        -o StrictHostKeyChecking=no \
         -o UserKnownHostsFile=/dev/null -o "SetEnv a=b" \
         sshc.${SSHD} -v

#		-o "UserKnownHostsFile ssh/testdata/known-hosts" \
#		-i ssh/testdata/id_ecdsa \

# Use openssh client
ssh/openssh-client:
	ssh -v  -p 15022  \
		-o StrictHostKeyChecking=no \
		localhost env

ssh:
	 ssh -o StrictHostKeyChecking=no  -J localhost:2222 sshc.${SSHD} -v


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

WORKLOAD_NAMESPACE=sshc


gcp/setup:
	gcloud --project ${PROJECT_ID} iam service-accounts create k8s-${WORKLOAD_NAMESPACE} \
	  --display-name "Service account with access to ${WORKLOAD_NAMESPACE} k8s namespace" || true

	# Grant the GSA running the workload permission to connect to the config clusters in the config project.
	# Will use the 'SetQuotaProject' - otherwise the GKE API must be enabled in the workload project.
	gcloud --project ${CONFIG_PROJECT_ID} projects add-iam-policy-binding \
			${CONFIG_PROJECT_ID} \
			--member="serviceAccount:k8s-${WORKLOAD_NAMESPACE}@${PROJECT_ID}.iam.gserviceaccount.com" \
			--role="roles/container.clusterViewer"
	# This allows the GSA to use the GKE and other APIs in the 'config cluster' project.
	gcloud --project ${CONFIG_PROJECT_ID} projects add-iam-policy-binding \
			${CONFIG_PROJECT_ID} \
			--member="serviceAccount:k8s-${WORKLOAD_NAMESPACE}@${PROJECT_ID}.iam.gserviceaccount.com" \
			--role="roles/serviceusage.serviceUsageConsumer"

	# Also allow the use of TD
	gcloud projects add-iam-policy-binding ${PROJECT_ID} \
	  --member serviceAccount:k8s-${WORKLOAD_NAMESPACE}@${PROJECT_ID}.iam.gserviceaccount.com \
	   --role roles/trafficdirector.client

	gcloud secrets add-iam-policy-binding mesh \
        --member=serviceAccount:k8s-${WORKLOAD_NAMESPACE}@${PROJECT_ID}.iam.gserviceaccount.com \
        --role="roles/secretmanager.secretAccessor"

# 6 free versions, 10k ops
gcp/secret:
	gcloud secrets create mesh --replication-policy="automatic"
	gcloud secrets versions add mesh --data-file="/path/to/file.txt"

# Helper to create a secret for the debug endpoint.
init-keys:
	mkdir -p ${OUT}/ssh
	(cd ${OUT}/ssh; ssh-keygen -t ecdsa -f id_ecdsa -N "")
	cp ${HOME}/.ssh/id_ecdsa.pub ${OUT}/ssh/authorized_keys

WORKLOAD_NAMESPACE?=default

k8s/secret: init-keys
	kubectl -n ${WORKLOAD_NAMESPACE} delete secret sshdebug || true
	kubectl -n ${WORKLOAD_NAMESPACE} create secret generic \
 		sshdebug \
 		--from-file=authorized_key=${OUT}/ssh/authorized_keys \
 		--from-file=cmd=cmd.json \
 		--from-file=ssd_config=sshd_config \
 		--from-file=id_ecdsa=${OUT}/ssh/id_ecdsa \
 		--from-file=id_ecdsa.pub=${OUT}/ssh/id_ecdsa.pub
	rm -rf ${OUT}/ssh

