#!/bin/bash

CA_DIR=${CA_DIR:-.}
TRUST_DOMAIN=${TRUST_DOMAIN:-cluster.local}
WORKLOAD_NAMESPACE=${WORKLOAD_NAMESPACE:-testns}
WORKLOAD_SA=${WORKLOAD_SA:-default}
OUT=${OUT:-.}

  # // SSH certificates:
  #//
  #//ssh-keygen -t rsa -N '' -C 'ca' -f ca
  #// -N'' - no pass
  #// -C - comment
  #// Out: ca, ca.pub
  #//
  #// Client cert:
  #//   ssh-keygen -s ca -I test@dmesh id_rsa.pub
  #// Server cert:
  #//   ssh-keygen -s ca -h -I test.dmesh /etc/host/ssh_host_ecdsa_key.pub
  #// -h == host
  #// -I hostname
  #// Out: id_cert.pub
  #//
  #// ssh-keygen -L: display cert
  #//
  #// Serial, Valid, Principals, Ext, CriticalOpts, keyId
  #// Ext: permit pty, x11, port, user-rc
  #//
  #// .authorized:
  #// .known-hosts:
  #// @cert-authority *.dmesh.com ssh-rsa AAAA.. ca@...
  #//
  #// echo "TrustedUserCAKeys /etc/ssh/ca.pub" >> /etc/ssh/sshd_config

function ssh_initca() {
  # -N '' - no pass
  # -C 'ca' - comment
  # -f ca - file
  # -q - quiet
  ssh-keygen -q -t ecdsa -m PEM -N '' -C 'ca' -f ${CA_DIR}/ca
  # TODO: upload to k8s and GCP secret

}


# Other useful commands:
#  -i - import
#  -e - export to RFC4716, PKCS8, PEM ( PEM, SSH2 PUBLIC KEY block, comment )
# -l - show fingerprint (256 SHA256:.... comment (ECDSA)

# known_hosts:
# -R hostname - remove hostname
# -F host - find hostname
# -H - hash known_hosts, both keys and addresses
#

# -r -g - print DNS TYPE44 records with fingerprint for host
# If DNS is secure, can be used to get the public key

# -L - print content of certificate

# Cert options:
# clear
# critical:name=content
# extension:name=content
# force-command=command
# no-port-forwarding
# permit-port-forwarding
#

# Must be run in the
function ssh_init() {
 # Generate the private key and public
 ssh-keygen -q -m PEM -t ecdsa -N '' -C '${WORKLOAD_SA}@${WORKLOAD_NAMESPACE}.${TRUST_DOMAIN}' -f ${OUT}/id_ecdsa

 # Sign the public using a local ca
 # -I - identity to include in certificate, by default email
 ssh-keygen -s ${CA_DIR}/ca -m PEM -I ${WORKLOAD_SA}@${WORKLOAD_NAMESPACE}.${TRUST_DOMAIN} ${OUT}/id_ecdsa.pub

 # -n principals - comma separated list of principals (user, hostname)
 # -O - option for certificate
 # -V  validity - exp or start:exp, in YYYYMMDD format or +52w

 # -h - host identity
 ssh-keygen -s ${CA_DIR}/ca -m PEM -h  -I ${WORKLOAD_SA}.${WORKLOAD_NAMESPACE}.${TRUST_DOMAIN} ${OUT}/id_ecdsa.pub

 CA=$(cat ${CA_DIR}/ca.pub)

 echo "cert-authority ${CA}" > ${OUT}/authorized-keys
 echo "@cert-authority * ${CA}" > ${OUT}/known-hosts

 cat <<EOF > ${OUT}/sshd_config
 Port 15022
 AddressFamily any
 ListenAddress 0.0.0.0
 ListenAddress ::
 Protocol 2
 LogLevel INFO
 # Workload identity shared for client and server
 HostKey ${OUT}/id_ecdsa
 PermitRootLogin yes
 AuthorizedKeysFile	${OUT}/authorized_keys
 PasswordAuthentication no
 PermitUserEnvironment yes
 AcceptEnv LANG LC_*
 PrintMotd no
 UsePAM no
 Subsystem	sftp	/usr/lib/openssh/sftp-server
EOF
#	// -f config
#	// -c host_cert_file
#	// -d debug - only one connection processed
#	// -e debug to stderr
#	// -h or -o HostKey
#	// -p or -o Port

	echo "/usr/sbin/sshd -f ${OUT}/sshd_config -e -D -p 15022"

 # TODO: make a Secret in k8s and GCP
}

if [[ ${1} = "test" ]] ; then
  ssh_initca
  ssh_init
fi
