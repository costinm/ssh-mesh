ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
OUT?=krun

# Helper to create a secret for the debug endpoint.
#
# WIP: alternative is to deploy a SSH cert authoritiy in the config cluster, will be
# auto-detected and used.

${HOME}/.ssh/id_ecdsa:
	mkdir -p ${HOME}/.ssh
	(cd ${HOME}/.ssh; ssh-keygen -t ecdsa -f id_ecdsa -N "")

WORKLOAD_NAMESPACE?=fortio

# Create an initial secret by cloning this VM secret
clone-ssh: ${HOME}/.ssh/id_ecdsa
	kubectl -n ${WORKLOAD_NAMESPACE} delete secret sshdebug || true
	kubectl -n ${WORKLOAD_NAMESPACE} create secret generic \
                sshdebug \
                --from-file=authorized_key_1=${HOME}/.ssh/id_ecdsa.pub \
                --from-file=id_ecdsa=${HOME}/.ssh/id_ecdsa \
                --from-file=id_ecdsa.pub=${HOME}/.ssh/id_ecdsa.pub
