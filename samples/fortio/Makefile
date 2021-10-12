
# GKE cluster used
PROJECT_ID?=wlhe-cr
# Region where CR will be deployed
REGION?=us-central1
# Namespace to attach to.
WORKLOAD_NAMESPACE?=fortio
SERVICE?=fortio-cr

export CLOUDRUN_SERVICE_ACCOUNT
export WORKLOAD_NAMESPACE
export PROJECT_ID


# Enable the built-in sshd server, with cert auth. Temp, will move to a config map in cluster
#SSH_DEBUG_ARGS=--set-env-vars="SSH_AUTH=$(shell cat ~/.ssh/id_ecdsa.pub)"

# SSH to the deployed CloudRun using HBONE
ssh: CR_URL=$(shell gcloud run services --project ${PROJECT_ID} --region ${REGION} describe ${SERVICE} --format="value(status.address.url)")
ssh:
	ssh  -F /dev/null  \
        -o StrictHostKeyChecking=no -o "UserKnownHostsFile /dev/null" \
 	    -o ProxyCommand='hbone ${CR_URL}:443/_hbone/22' \
     	root@proxybase ${SSH_ARGS}

#config_dump: CR_URL=$(shell gcloud run services --project ${PROJECT_ID} --region ${REGION} describe ${SERVICE} --format="value(status.address.url)")
#config_dump:
##	 ssh -F /dev/null -o StrictHostKeyChecking=no \
##        -o "UserKnownHostsFile /dev/null" \
## 	    -o ProxyCommand='hbone ${CR_URL}/_hbone/22' -- sh curl localhost:15000/config_dump
#	@curl -v  ${CR_URL}/fortio/fetch2/?url=http%3A%2F%2Flocalhost%3A15000%2Fconfig_dump

config_dump: CR_URL=$(shell gcloud run services --project ${PROJECT_ID} --region ${REGION} describe ${SERVICE} --format="value(status.address.url)")
config_dump:
	 @ssh -F /dev/null -o StrictHostKeyChecking=no \
        -o "UserKnownHostsFile /dev/null" \
 	    -o ProxyCommand='hbone ${CR_URL}:443/_hbone/22' -- sh curl localhost:15000/config_dump

config_dump_ssh: config_dump

