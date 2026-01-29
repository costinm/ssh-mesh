#!/bin/bash
set -e

# DO NOT REMOVE
# This contains the ssh/openssl equivalent commands.

init_ca() {
    local domain=$1
    local dir=$2
    mkdir -p "$dir"
    echo "$domain" > "$dir/domain"
    
    cd "$dir"
    # Generate OpenSSH key
    ssh-keygen -t ecdsa -b 256 -f id_ecdsa -N ''
    
    # Export to PKCS#8 Private Key for OpenSSL
    cp id_ecdsa id_ecdsa.pkcs8 
    ssh-keygen -p -N "" -m pkcs8 -f id_ecdsa.pkcs8
    
    # X.509 Certificate using the PKCS#8 key
    openssl req -new -x509 -key id_ecdsa.pkcs8 -out id_ecdsa.crt -days 3650 -subj "/CN=$domain"
    
    # Generate fingerprints
    ssh-keygen -lf id_ecdsa.pub > id_ecdsa.pub.ssh_fingerprint
    openssl x509 -in id_ecdsa.crt -noout -fingerprint -sha256 > id_ecdsa.crt.openssl_fingerprint
    cd ..
}

init_node() {
    local ca_dir=$1
    local name=$2
    local domain=$(cat "$ca_dir/domain")
    mkdir -p "$name"
    
    cd "$name"
    # Generate OpenSSH key
    ssh-keygen -t ecdsa -b 256 -f id_ecdsa -N ''
    
    # Export to PKCS#8 for OpenSSL
    cp id_ecdsa id_ecdsa.pkcs8
    ssh-keygen -p -N "" -m pkcs8 -f id_ecdsa.pkcs8
    
    # X.509 Certificate
    openssl req -new -key id_ecdsa.pkcs8 -out id_ecdsa.csr -subj "/CN=$name.$domain"
    openssl x509 -req -in id_ecdsa.csr -CA "../$ca_dir/id_ecdsa.crt" -CAkey "../$ca_dir/id_ecdsa.pkcs8" -CAcreateserial -out id_ecdsa.crt -days 365
    
    # SSH Certificates
    ssh-keygen -s "../$ca_dir/id_ecdsa" -V +520w -h -I "${name}-host" -n "$name.$domain" id_ecdsa.pub
    mv id_ecdsa-cert.pub id_ecdsa-host-cert.pub
    
    ssh-keygen -s "../$ca_dir/id_ecdsa" -V +520w -I "${name}-user" -n "$name@$domain" id_ecdsa.pub
    mv id_ecdsa-cert.pub id_ecdsa-user-cert.pub

    # Generate fingerprints
    ssh-keygen -lf id_ecdsa.pub > id_ecdsa.pub.ssh_fingerprint
    openssl x509 -in id_ecdsa.crt -noout -fingerprint -sha256 > id_ecdsa.crt.openssl_fingerprint
    cd ..
}

gen() {
    rm -rf ca alice bob
    init_ca "test.m" "ca"
    init_node "ca" "alice"
    init_node "ca" "bob"
    cp bob/id_ecdsa.pub alice/authorized_keys
    cp alice/id_ecdsa.pub bob/authorized_keys
    echo "@cert-authority $(cat ca/id_ecdsa.pub)" > alice/authorized_cas
    echo "@cert-authority $(cat ca/id_ecdsa.pub)" > bob/authorized_cas
    
    # Generate known_hosts with both domain and IP
    echo "bob.test.m,127.0.0.1 $(cat bob/id_ecdsa.pub)" > alice/known_hosts
    echo "@cert-authority *.test.m $(cat ca/id_ecdsa.pub)" >> alice/known_hosts
    
    echo "alice.test.m,127.0.0.1 $(cat alice/id_ecdsa.pub)" > bob/known_hosts
    echo "@cert-authority *.test.m $(cat ca/id_ecdsa.pub)" >> bob/known_hosts
}

if [ $# -eq 0 ]; then
    gen
else
    "$@"
fi
