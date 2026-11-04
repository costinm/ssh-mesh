# mesh-acme

Small pure-Rust ACME (Let's Encrypt) client library, HTTP-01 only. The CLI is
`meshkeys acme` (crate `ssh-mesh`). Run `renew` periodically
(e.g. from a mesh-init job) as an unprivileged user; it replaces cron + certbot.
State lives in Caddy's on-disk layout, so a Caddy data dir can be copied in.

    meshkeys acme renew [--home DIR] [--config FILE] [--staging] [--force] [--dry-run]
    meshkeys acme add <DOMAIN>... [--home DIR] [--config FILE] [--staging]

`add` validates the names (no wildcards), appends new ones to `domains` in the
config (created if missing, comments preserved) and issues certificates now,
printing each certificate path. It exits non-zero if any issuance fails; the
names stay in the config so `renew` retries them.

Config `<home>/etc/mesh-acme.toml` (missing file or empty `domains` => exit 0):

    email = "admin@example.m"          # optional
    # directory = "https://acme-staging-v02.api.letsencrypt.org/directory"
    domains = ["dev1.h.webinf.info"]   # one certificate per name
    renew_days = 30                    # optional

## Development homes and HTTP serving

The CLI and ssh-mesh use one shared ACME home and select the same
default: `MESH_ACME_HOME`, readable `/home/acme`, or `<ssh-mesh home>/acme`.
The ssh-mesh home prefers readable `/home/ssh-mesh/etc`, otherwise `$HOME/etc`.

    meshkeys acme add example.org
    meshkeys acme renew --dry-run

Use `--home` and `acme_home` only for an explicit alternative. mesh-init must pass the plain HTTP socket
with name `http80` and the TLS socket with name `https`; the CLI does not
bind either port. HTTP-01 writes files, not DNS records. Verify a test file
under `www/.well-known/acme-challenge/` is readable over the domain's port 80
before requesting a certificate.

After issuance, ssh-mesh's `certs/reload` command installs certificates without
a restart. Supply the explicit certificate paths for a newly added domain;
reload without paths only rereads the previously installed set. Issuance and
renewal do not call reload automatically. Scheduling `renew` is separate from
adding a domain.

## Layout (D = `<home>/.local/share/caddy`, ISSUER = e.g. `acme-v02.api.letsencrypt.org-directory`)

- `D/certificates/ISSUER/NAME/NAME.{crt,key,json}` (dirs 0750, files 0640; `*.x` is `wildcard_.x`)
- `D/acme/ISSUER/users/USER_DIR/USERNAME.{key,json}` (dirs 0700, files 0600;
  `users/<email>/<local-part>.*`, or `users/default/default.*` without email)
- HTTP-01 tokens: `<home>/www/.well-known/acme-challenge/<token>` (removed afterwards)

## Migrating from Caddy

    cp -a <caddy data>/{certificates,acme} /home/acme/.local/share/caddy/
    chown -R 151:150 /home/acme/.local/share/caddy
    chmod -R u=rwX,go= /home/acme/.local/share/caddy/acme
    find /home/acme/.local/share/caddy/certificates -type d -exec chmod 0750 {} +
    find /home/acme/.local/share/caddy/certificates -type f -exec chmod 0640 {} +

The Caddy account (key + `location` in the json) is reused, not re-created.
SEC1 (`EC PRIVATE KEY`) and PKCS#8 keys are both read; new keys are written as PKCS#8.
