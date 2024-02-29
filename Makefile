include tools/common.mk

REGION?=us-central1

all: all/sshm

build: build/sshm

build/sshm: BIN=sshm
build/sshm: _build


all/fortio: BIN=sshm
all/fortio: DOCKER_IMAGE=fortio-sshm
all/fortio:
	#$(MAKE) _push BASE_IMAGE=fortio/fortio:latest BIN=sshc
	docker build -t costinm/fortio-sshm:latest -f manifests/Dockerfile.fortio manifests/
	docker push costinm/fortio-sshm:latest

# Expected sizes:
# v1:
# - sshc 9.8M->6.6M
# - sshd + h2c: 10.3/6.9

push/sshm:
	$(MAKE) _push BIN=sshm

push: push/sshm

all/sshm: build/sshm push/sshm

# Replace the CR service
cr/replace:
	cat manifests/cloudrun.yaml | \
	DEPLOY="$(shell date +%H%M)" IMG="$(shell cat ${OUT}/.image)" envsubst | \
     gcloud alpha run --project ${PROJECT_ID} services replace -

cr/fortio:
	cat manifests/cloudrun-fortio.yaml | \
	DEPLOY="$(shell date +%H%M)" IMG="$(shell cat ${OUT}/.image)" envsubst | \
     gcloud alpha run --project ${PROJECT_ID} services replace -

proxy/fortio:
	gcloud run services proxy costin-fortio --region us-central1 --port 8082

# Build, push to gcr.io, update the cloudrun service
# Cloudrun requires gcr or artifact registry

cr: all/sshm cr/replace


crbindings: REGION=us-central1
crbindings:
	gcloud run services add-iam-policy-binding  --project ${PROJECT_ID} --region ${REGION} sshc  \
      --member="serviceAccount:k8s-default@${PROJECT_ID}.iam.gserviceaccount.com" \
      --role='roles/run.invoker'

crauth:
	gcloud run services add-iam-policy-binding  --project ${PROJECT_ID} --region ${REGION} sshc  \
      --member="user:${GCLOUD_USER}" \
      --role='roles/run.invoker'

crauth/all: REGION=us-central1
crauth/all:
	gcloud run services add-iam-policy-binding   --project ${PROJECT_ID} --region ${REGION} sshc  \
      --member="allUsers" \
      --role='roles/run.invoker'


# SSH via a local jumphost
jssh:
	ssh -o StrictHostKeyChecking=no  -J localhost:15022 sshc.${SSHD} -v

# SSH to a CR service using a h2 tunnel.
# Works if sshd is handling the h2 port, may forward to the app.
# Useful if scaled to zero, doesn't require maintaining an open connection (but random clone)
cr/h2ssh: CR_URL?=$(shell gcloud run services --project ${PROJECT_ID} --region ${REGION} describe ${SERVICE} --format="value(status.address.url)")
cr/h2ssh:
	ssh -o ProxyCommand="${HOME}/go/bin/h2t ${CR_URL}_ssh/tun" \
        -o StrictHostKeyChecking=no \
        -o "SetEnv a=b" \
         sshc.${SSHD} -v

# Using the test certs:
#		-o "UserKnownHostsFile ssh/testdata/known-hosts" \
#		-i ssh/testdata/id_ecdsa \

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


perf-test-setup:
    # Using goben instead of iperf3
	goben -defaultPort :5201 &

perf-test:
	# -passiveClient -passiveServer
	goben -hosts localhost:15201  -tls=false -totalDuration 3s

perf-test-setup-iperf:
    # Using goben instead of iperf3
	iperf3 -s -d &

