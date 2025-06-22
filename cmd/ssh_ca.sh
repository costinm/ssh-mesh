#!/bin/bash


function help() {
  cat <<EOF
Minimal standalone SSH CA operation.

Environment:
DOMAIN = FQDN for the generated identities. Defaults to "hostname -d" (domainname)
         of current host.
BASE = base of the config filesystem. Defaults to ${HOME}/.ssh

Configs for each hostname will be under $BASE/$DOMAIN/$NAME

Commands:

ca - creates a CA for the domain, under $BASE/$DOMAIN/ca/
mesh NAME - creates workload identity, under $BASE/$DOMAIN/$NAME


EOF

}

# For testdata:
# export BASE=`pwd`/testdata
# export DOMAIN=test.mesh.internal

# Domain of the CA host - may have istio-system namespace
# to share the root CA.
DOMAIN=${DOMAIN:-$(hostname -d)}

# NAMESPACE for created identities.
#NAMESPACE=${NAMESPACE:-${DOMAIN%%.*}}
NAMESPACE=${NAMESPACE:-default}

# TOP DOMAIN
#DOMAIN=$(echo $HDOMAIN | sed 's/[^\.]*\.//')

# Default is to store the CA in the .ssh directory for the user running
# the CA.
BASE=${BASE:-${HOME}/.ssh}
CA_DIR=${CA_DIR:-${BASE}/${DOMAIN}/ca}


# Serial, Valid, Principals, Ext, CriticalOpts, keyId
# Ext: permit pty, x11, port, user-rc
# Cert options:
# clear
# critical:name=content
# extension:name=content
# force-command=command
# no-port-forwarding
# permit-port-forwarding
#

# initca will initialize a SSH CA, using ecdsa keys.
# The 'CA' is just a regular ssh node - each node can sign.
function ca() {
  local d=${CA_DIR}
  local u=ca
  local h=${u}.${DOMAIN}

  if [ ! -f ${d}/id_ecdsa ] ; then
    mkdir -p ${d}
    ssh-keygen -q -t ecdsa -m PKCS8 -N '' -C "ca.${DOMAIN}" \
      -f ${d}/id_ecdsa
  fi
  local CA=$(< ${CA_DIR}/id_ecdsa.pub)

  grep "$CA" $d/authorized_keys > /dev/null
  if [ $? != "0" ]; then
    echo -e "\ncert-authority ${CA}\n" >> $d/authorized_keys
    echo -e "\n@cert-authority * ${CA}\n" >> ${CA_DIR}/known_hosts
  fi

  ssh2tlsCA $d
  _conf ca $d $CA

}

# Convert a ssh key generated with `ssh-keygen -q -t ecdsa -m PKCS8` to a self-signed CA cert.
function ssh2tlsCA() {
  local d=${1:-CA_DIR}

  # tls.key, tls.crt, ca.crt are used by CertManager, K8S and Istio
  # BEGIN EC PRIVATE KEY block
  cp $d/id_ecdsa $d/tls.key
  #openssl ecparam -name prime256v1 -genkey -noout -out ${CA_DIR}/tls.key
  # BEGIN PUBLIC KEY block
  openssl ec -in ${d}/tls.key -pubout -out ${Cd}/tls.pub

  cat << EOF > ${d}/csr.conf
[ req ]
encrypt_key = no
prompt = no
utf8 = yes
default_md = sha256
default_bits = 4096
req_extensions = req_ext
x509_extensions = req_ext
distinguished_name = req_dn

[ req_ext ]
subjectKeyIdentifier = hash
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, nonRepudiation, keyEncipherment, keyCertSign

[ req_dn ]
O = ${DOMAIN}
CN = ${DOMAIN}
EOF

  openssl req -new -sha256 -key ${d}/tls.key -config ${d}/csr.conf -out ${d}/tls.csr
  openssl x509 -req -sha256 -days 365 \
     -signkey ${d}/tls.key \
     -extensions req_ext -extfile ${d}/csr.conf \
     -in ${d}/tls.csr \
     -out ${d}/tls.crt

  cp $d/id_ecdsa.pub $d/ssh_host_ecdsa_key.pub
  ssh-keygen -s ${d}/id_ecdsa -m PEM -h -I ${h} -n ${h} ${d}/ssh_host_ecdsa_key.pub
  cp $d/id_ecdsa.pub $d/host.pub
  ssh-keygen -s ${d}/id_ecdsa -m PEM -h -I ${h} -n ${h} ${d}/host.pub

  ssh-keygen -s ${d}/id_ecdsa -m PEM  -I ${h} -n ${u} ${d}/id_ecdsa.pub

#  openssl pkcs12 -export -inkey ${d}/tls.key -in ${d}/tls.crt \
#    -out ${d}/tls.pfx

}


# Common ssh-keygen params:
# -q - quiet
# -t ecdsa - type of key to generate
# -m PEM - save as PEM
# -N - password (don't ask, use that)
# -C - comment, used to hold the FQDN identity.

# Other useful commands/args:
#  -i - import
#  -e - export to RFC4716, PKCS8, PEM ( PEM, SSH2 PUBLIC KEY block, comment )
# -l - show fingerprint (256 SHA256:.... comment (ECDSA)
# -R hostname - remove hostname
# -F host - find hostname
# -H - hash known_hosts, both keys and addresses
# -r -g - print DNS TYPE44 records with fingerprint for host
#    If DNS is secure, can be used to get the public key
# -L - print content of certificate

#
# .authorized:
#
# .known-hosts:
# @cert-authority *.dmesh.com ssh-rsa AAAA..  ca@...
#
# echo "TrustedUserCAKeys /etc/ssh/ca.pub" >> /etc/ssh/sshd_config

# Create the ssh file in a directory
# Can be used with $HOME/.ssh for a new host.
# CA_DIR must be set.
function mesh() {
  local u=$1
  local NS=${2:-$NAMESPACE}

  local d=${BASE}/${DOMAIN}/$u

  # TODO: multiple CAs support
  local CA=$(< ${CA_DIR}/id_ecdsa.pub)

  mkdir -p $d

  # Opinionated naming (version 1). 
  local h=${u}.${DOMAIN}
  local uid=${u}@${DOMAIN}

  if [ ! -f $d/id_ecdsa ]; then
      ssh-keygen -q -t ecdsa -m PEM -f $d/id_ecdsa -N '' -C $h
  fi


  #openssl ecparam -name prime256v1 -genkey -noout -out ${d}/tls.key
  cp $d/id_ecdsa $d/tls.key

  openssl ec -in ${d}/tls.key -pubout -out ${d}/tls.pub

  cat << EOF > ${d}/csr.conf
[ req ]
encrypt_key = no
prompt = no
utf8 = yes
default_md = sha256
default_bits = 4096
req_extensions = req_ext
x509_extensions = req_ext
distinguished_name = req_dn

[ req_ext ]
subjectKeyIdentifier = hash
basicConstraints = critical, CA:false
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName=@san

[ san ]
DNS.1 = $u.$DOMAIN

[ req_dn ]
CN = $u.$DOMAIN

EOF

  openssl req -new -sha256 \
    -key ${d}/tls.key \
    -config ${d}/csr.conf \
    -out ${d}/tls.csr


  openssl x509 -req -sha256 -days 365 \
    -CAkey ${CA_DIR}/tls.key -CAcreateserial -CA ${CA_DIR}/tls.crt \
    -extensions req_ext -extfile ${d}/csr.conf \
    -in ${d}/tls.csr \
    -out ${d}/tls.crt

#  openssl pkcs12 -export -inkey ${d}/tls.key -in ${d}/tls.crt \
#    -out ${d}/tls.pfx

  # CA options:
   # -n principals - comma separated list of principals (user, hostname)
   # -O - option for certificate
   # -V  validity - exp or start:exp, in YYYYMMDD format or +52w
  # -h - host mode (default is client)
  # -I - identity to include in certificate
  # Out: extension _cert.pub


  cp $d/id_ecdsa $d/ssh_host_ecdsa_key
  cp $d/id_ecdsa.pub $d/ssh_host_ecdsa_key.pub
  ssh-keygen -s ${CA_DIR}/id_ecdsa -m PEM -h -I ${h} -n ${h} ${d}/ssh_host_ecdsa_key.pub
  cp $d/id_ecdsa.pub $d/host.pub
  ssh-keygen -s ${CA_DIR}/id_ecdsa -m PEM -h -I ${h} -n ${h} ${d}/host.pub

  ssh-keygen -s ${CA_DIR}/id_ecdsa -m PEM  -I ${h} -n ${u} ${d}/id_ecdsa.pub

 grep "$CA" $d/known_hosts > /dev/null 2>&1
 if [ $? != "0" ]; then
   echo -e "\n@cert-authority * ${CA}\n" >> $d/known_hosts
 fi
 grep "$CA" $d/authorized_keys > /dev/null 2>&1
 if [ $? != "0" ]; then
   echo -e "\ncert-authority ${CA}\n" >> $d/authorized_keys
 fi

  # To keep it simple, assume the configs are mounted on /.sshm
  local mntdir=/.sshm

 # On each pod/workload, expect the secret to be mounted on /var/run/secrets/ssh
 # This is a user-space sshd.
 cat <<EOF > $d/sshd_config
Port 15022
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::
Protocol 2
LogLevel INFO
HostKey ${mntdir}/ssh_host_ecdsa_key
TrustedUserCAKeys ${mntdir}/ssh_user_key.pub
AuthorizedKeysFile	${mntdir}/authorized_keys
PermitRootLogin yes
PasswordAuthentication no
UsePAM no
PermitUserEnvironment yes
AcceptEnv LANG LC_*
PrintMotd no
Subsystem	sftp	/usr/lib/openssh/sftp-server
EOF

  _conf $u $d
}

function _conf() {
  local u=$1
  local d=$2

  jq --null-input \
    --arg id "${u}" \
    --arg ns "${NS}" \
    --rawfile idp ${d}/id_ecdsa-cert.pub \
    --rawfile ak ${d}/authorized_keys \
    --rawfile chp ${d}/host-cert.pub \
    --rawfile tlskey ${d}/tls.key \
   '{ "id": ($id), "namespace": ($ns), "tls.key": ($tlskey), "authorized_keys": ($ak), "id_ecdsa_cert.pub": ($idp), "cert_host.pub": ($chp)}' \
   > $d/sshm.json
}

# Save the config for a SA to K8S as a secret
function k8s() {
  local n=${1:-default}
  local ns=${2:-${NAMESPACE}}

  local d=${CA_DIR}/$ns-$n

  kubectl -n ${ns} create serviceAccount ${n} || true

  # Can get tokens for the GSA
  kubectl -n ${ns} annotate serviceaccount ${n} \
      iam.gke.io/gcp-service-account=${ns}-${n}@${PROJECT_ID}.iam.gserviceaccount.com

  kubectl -n $ns create secret generic $n --from-file $d/sshm.json
}

# Save the config for a SA to GCP, creating a matching Google SA
# This can be used with CloudRun/etc.
function gcp() {
  local n=${1:-default}
  local ns=${2:-$NAMESPACE}

  local d=${CA_DIR}/$ns-$n

  gcloud secrets --project $PROJECT_ID create ${ns}-${n} --data-file=$d/sshm.json
  # may exist
  gcloud iam --project $PROJECT_ID service-accounts create ${ns}-${n} \
     --display-name="${n}.${ns}" || true

  gcloud secrets --project $PROJECT_ID add-iam-policy-binding ${ns}-${n} \
    --member=serviceAccount:${ns}-${n}@${PROJECT_ID}.iam.gserviceaccount.com \
    --role='roles/secretmanager.secretAccessor'

  # The K8S SA can use the GSA
  gcloud iam --project $PROJECT_ID \
       service-accounts add-iam-policy-binding \
       ${ns}-${n}@{PROJECT_ID}.iam.gserviceaccount.com \
      --member=serviceAccount:${PROJECT_ID}.svc.id.goog[${ns}/${n}] \
      --role='roles/iam.workloadIdentityUser'

}

# Extra permissions for the CA service account
function gcp_ca() {
  # The mesh auth service will run as 'ca.istio-system' and have additional permissions
  gcloud secrets --project $PROJECT_ID \
    add-iam-policy-binding ${ns}-${n} \
    --member=serviceAccount:${ns}-${n}@${PROJECT_ID}.iam.gserviceaccount.com \
    --role='roles/secretmanager.secretVersionAdder'
}




CMD=$1
shift
$CMD $*
