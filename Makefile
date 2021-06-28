
KO_DOCKER_REPO ?= gcr.io/dmeshgate/ssh-signerd
export KO_DOCKER_REPO

ko/build: ko/sshca ko/sshd

ko/sshca:
	cd sshca && ko publish --bare ./ssh-signerd -t latest

ko/sshd:
	cd ssh && ko publish --bare ./sshd -t latest


# Use openssh client
ssh/openssh-client:
	ssh -v  -p 15022  \
		-o "UserKnownHostsFile sshca/testdata/known-hosts" \
		-o StrictHostKeyChecking=yes \
		-i sshca/testdata/id_ecdsa \
		localhost env

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

ssh/getcert-k8s: CRT=$(shell cat testdata/keygen/id_ecdsa.pub)
ssh/getcert-k8s:
	echo {\"public\":\"${CRT}\"} | \
 		grpcurl -plaintext  -d @   [::1]:14021 ssh.SSHCertificateService/CreateCertificate
