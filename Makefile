ROOT_DIR?=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
OUT?=${ROOT_DIR}/../out/cert-ssh

BASE_DISTROLESS?=gcr.io/distroless/static

# Base image -
BASE_DEBUG?=ubuntu:bionic

# Where to push
DOCKER_REPO?=ghcr.io/costinm/ssh-mesh
export DOCKER_REPO

GOPROXY?=https://proxy.golang.org
export GOPROXY

all: build push/gate push/sshd

build:
	mkdir -p ${OUT}/etc/ssl/certs/
	cp /etc/ssl/certs/ca-certificates.crt ${OUT}/etc/ssl/certs/
	mkdir -p ${OUT}/usr/local/bin
	#CGO_ENABLED=0  GOOS=linux GOARCH=amd64 time
	cd cmd/sshc && go build \
		-o ${OUT}/usr/local/bin/ \
		.

#docker:
#	docker build -t ${DOCKER_REPO}/sshd -f tools/docker/Dockerfile.sshd ${OUT}
#	docker build -t ${DOCKER_REPO}/mesh -f tools/docker/Dockerfile.sshmesh ${OUT}
#
#push/docker:
#	docker push ${DOCKER_REPO}/sshd
#	docker push ${DOCKER_REPO}/gate


_push:
	(export SSHDRAW=$(shell cd ${OUT} && tar -cf - etc ${PUSH_FILES} | \
					  gcrane append -f - -b ${BASE_DEBUG} \
						-t ${DOCKER_REPO}/sshc:latest \
					   ) && \
	gcrane mutate $${SSHDRAW} --entrypoint /${PUSH_FILES} \
	)

#	 && \
#	\
#	gcrane rebase --rebased ${DOCKER_REPO}/gate-distroless:latest \
#	   --original $${SSHDRAW} \
#	   --old_base ${BASE_DEBUG} \
#	   --new_base ${BASE_DISTROLESS} \
#	)

# Append files to an existing container
push/gate:
	PUSH_FILES=usr/local/bin/sshc $(MAKE) _push

# Push to a GCR repo for CR
gcp/push: DOCKER_REPO=gcr.io/dmeshgate/sshmesh
gcp/push: push

push: build push/gate

#push/sshd:
#	PUSH_FILES=usr/local/bin/sshd $(MAKE) _push

cr/replace:
	gcloud alpha run services replace manifests/cloudrun.yaml

cr: gcp/push cr/replace

REGION?=us-central1
crauth:
	gcloud run services add-iam-policy-binding  --region ${REGION} sshc  \
      --member="user:costin@gmail.com" \
      --role='roles/run.invoker'
	gcloud run services add-iam-policy-binding  --region ${REGION} sshc  \
      --member="allUsers" \
      --role='roles/run.invoker'


crcurl:
	curl -v -H"Authorization: Bearer $(shell gcloud auth print-identity-token)" https://sshc-yydsuf6tpq-uc.a.run.app/


crssh: crcurl
	ssh -o StrictHostKeyChecking=no  -J localhost:2222 sshc.s.webinf.duckdns.org -v

#		-o "UserKnownHostsFile ssh/testdata/known-hosts" \
#		-i ssh/testdata/id_ecdsa \

# Use openssh client
ssh/openssh-client:
	ssh -v  -p 15022  \
		-o StrictHostKeyChecking=no \
		localhost env

ssh:
	 ssh -o StrictHostKeyChecking=no  -J localhost:2222 sshc.s.webinf.duckdns.org -v


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

deps:
	go install github.com/google/go-containerregistry/cmd/gcrane@latest

PROJECT_ID?=dmeshgate
CONFIG_PROJECT_ID?=dmeshgate
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
