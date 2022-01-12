
Since CloudRun and docker doesn't support kubectl exec or port-forward, we add a minimal sshd server that is enabled
using a K8S Secret or environment variables. There are 2 ways to enable ssh fosshr debugging:

- create a Secret name sshdebug with the SSH private key and authorized_keys. See samples/ssh for setup example.
- add the SSH_AUTH env variable containing the authorized public
  key. `--set-env-vars="SSH_AUTH=$(cat ~/.ssh/id_ecdsa.pub)"`

You can ssh into the service and forward ports using a regular ssh client and a ProxyCommand that implements tunneling
over HTTP/2:

```shell

# Compile the proxy command
go install ./cmd/hbone

(cd samples/ssh; WORKLOAD_NAMESPACE=fortio make secret)
# Re-deploy the cloudrun service - or wait for it to scale to zero. The ssh is enabled on startup.

# Set with your own service URL
export SERVICE_URL=$(gcloud run services describe ${CLOUDRUN_SERVICE} --project ${PROJECT_ID} --region ${REGION} --format="value(status.address.url)")

ssh  -o ProxyCommand='hbone ${SERVICE_URL}:443/_hbone/22' root@${CLOUDRUN_SERVICE}

# or use "-F /dev/null" to disable any configured settings that may interfere, and 
# turn off SSH host checking since the tunnel is checking the TLS cert of the service:

ssh -F /dev/null -o StrictHostKeyChecking=no -o "UserKnownHostsFile /dev/null" \
    -o ProxyCommand='hbone ${SERVICE_URL}:443/_hbone/22' root@${CLOUDRUN_SERVICE}

```
