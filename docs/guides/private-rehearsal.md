# Private deployment rehearsal (operator guide)

How to install one Ruvee server on one Ubuntu 24.04 VPS, reachable only privately, with
**synthetic data only**, and take it through the rehearsal in
[deployment-rehearsal.md](../planning/deployment-rehearsal.md). It reuses what already exists:
`deploy/Caddyfile` and its generated headers, `ruvee-admin`, and the steps of
[database-roles.md](database-roles.md) and [server-backup-restore.md](server-backup-restore.md).
The host pieces are in `deploy/`.

> **Not a production deployment.** D-19 (independent review) is open and real data is refused by
> design: `ruvee-admin backup` backs up only a database named `ruvee_e2e_<hex>`. A rehearsal that
> passes shows that the procedure works on a real host. It approves nothing for real data.
> Nothing here has been run on a real server yet; the CI job "Deployment rehearsal host" runs
> §3 to §9 on a disposable Ubuntu 24.04 runner (what it does not cover is listed in §12).

## 1. The shape

```
 rehearsal laptop / phone ──(tailnet, WireGuard)──▶ VPS :443  Caddy (ruvee-caddy.service)
                                                     │  /           → apps/web/out (one build)
                                                     │  /api/*      → 127.0.0.1:4000
                                                     ▼
                                    ruvee-api.service (one process, runtime role)
                                                     ▼
                                    PostgreSQL 18 on localhost (fsync on)
 backups: /var/backups/ruvee ──copied──▶ separate backup storage
 offline: age identity, backup digests, OPAQUE setup copy (apart from each other and the backups)
```

| Piece                  | In `deploy/`                                                     | Installed as                                |
| ---------------------- | ---------------------------------------------------------------- | ------------------------------------------- |
| Caddy configuration    | `Caddyfile` (unchanged contract, HSTS on HTTPS)                  | read from `/opt/ruvee/current/deploy/`      |
| API unit               | `systemd/ruvee-api.service`                                      | `/etc/systemd/system/`                      |
| Caddy unit             | `systemd/ruvee-caddy.service`                                    | `/etc/systemd/system/`                      |
| Disk check             | `systemd/ruvee-diskcheck.{service,timer}`, `bin/ruvee-diskcheck` | `/etc/systemd/system/`                      |
| API environment        | `env/api.env.example`                                            | `/etc/ruvee/api.env` (root, 0600)           |
| Caddy environment      | `env/caddy.env.example`                                          | `/etc/ruvee/caddy.env` (root, 0644)         |
| Operator environment   | `env/operator.env.example`                                       | `/etc/ruvee/operator.env` (ruvee-ops, 0400) |
| `ruvee-admin` wrapper  | `bin/ruvee-admin`                                                | run as `sudo -u ruvee-ops …`                |
| PostgreSQL settings    | `postgresql/50-ruvee.conf`                                       | `/etc/postgresql/18/main/conf.d/`           |
| Journal cap            | `journald/50-ruvee.conf`                                         | `/etc/systemd/journald.conf.d/`             |
| Build manifest         | `bin/build-manifest`                                             | run in the release directory                |
| Synthetic sign-in page | `rehearsal/test-site/index.html`                                 | served on the rehearsal laptop only (§11)   |

Users: `ruvee-api` runs the API, `caddy` runs Caddy, `ruvee-ops` runs `ruvee-admin`. None can
log in. The API's user can read only its own OPAQUE setup file in `/etc/ruvee/api/` (0600): systemd
reads `api.env` as root, and `operator.env` belongs to `ruvee-ops`.

## 2. What you need before starting

- **The VPS:** x86-64, Ubuntu 24.04 LTS, 2 vCPU, 4 GB RAM (the build needs it; the services use
  far less, see the plan's measurements), 40 GB SSD, a 2 GB swap file. Console access from the
  provider, for when SSH is closed.
- **Private access:** a tailnet (Tailscale) with the VPS and the rehearsal devices in it, MagicDNS
  and HTTPS certificates enabled. The VPS's name, `<host>.<tailnet>.ts.net`, is the origin. (The
  alternative and its costs are in the plan, §2.3.)
- **Separate backup storage:** a location that is not the VPS (another machine you control, or an
  object store), reachable from the VPS for copying. Its credentials stay out of this repository.
- **An offline machine** for the age identity and the digests (§8).
- **The candidate commit** (§3) and its CI manifest artifact.

Never paste a private key, an identity, a password or a token into chat, an issue or a commit.
Every secret below is generated on the machine that keeps it.

## 3. The release: one commit, built reproducibly

The candidate is one full commit id, `<commit>`, whose CI run passed every job, including
"Deployment rehearsal host". That job publishes the artifact `deploy-rehearsal-<commit>`, holding
`build-manifest.txt`: the SHA-256 of every file the host will run or serve.

On the VPS, as an administrator (not root):

```bash
sudo install -d -o "$USER" /opt/ruvee/releases/<commit>
git clone https://github.com/<owner>/<repo>.git /opt/ruvee/releases/<commit>
cd /opt/ruvee/releases/<commit>
git checkout --detach <commit>
test "$(git rev-parse HEAD)" = <commit>
corepack enable
pnpm install --frozen-lockfile
pnpm turbo run build --filter=@ruvee/api --filter=@ruvee/web
deploy/bin/build-manifest > ../build-manifest-<commit>.txt
diff ../build-manifest-<commit>.txt <the CI build-manifest.txt for this commit>
sudo chown -R root:root /opt/ruvee/releases/<commit>
sudo ln -sfn /opt/ruvee/releases/<commit> /opt/ruvee/current
```

- The web export's build id is the commit, so the same commit builds to the same bytes anywhere
  (`RUVEE_BUILD_ID=<commit>` does the same outside a git checkout). The CI job checks this: it
  builds the commit a second time, from `git archive`, in `/opt/ruvee/releases`, and compares.
- An empty `diff` is required. Any difference stops the rehearsal: find out why first.
- The release keeps its development dependencies: `ruvee-admin restore` runs
  `node_modules/.bin/prisma migrate deploy`.
- Versions: use the Node.js, Caddy and PostgreSQL versions that CI recorded for this commit
  (`versions.txt` in the same artifact). Node.js from the official `linux-x64` tarball, checked
  against `SHASUMS256.txt` and its signature, extracted into `/usr/local` (the unit runs
  `/usr/local/bin/node`). PostgreSQL 18 from the PGDG apt repository. Caddy from the Caddy
  project's apt repository, held at that version (`apt-mark hold caddy`), with the package's own
  `caddy.service` disabled. `age` from Ubuntu.

## 4. The host

As root (or with sudo), once:

```bash
# Users and directories
for u in ruvee-api ruvee-ops; do
  useradd --system --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin "$u"
done
install -d -m 0755 /etc/ruvee
install -d -m 0700 -o ruvee-api -g ruvee-api /etc/ruvee/api
install -d -m 0700 -o ruvee-ops -g ruvee-ops /var/backups/ruvee

# PostgreSQL settings and the journal cap
install -m 0644 /opt/ruvee/current/deploy/postgresql/50-ruvee.conf /etc/postgresql/18/main/conf.d/
systemctl restart postgresql@18-main
install -d /etc/systemd/journald.conf.d
install -m 0644 /opt/ruvee/current/deploy/journald/50-ruvee.conf /etc/systemd/journald.conf.d/
systemctl restart systemd-journald
```

- **Firewall (ufw):** `default deny incoming`, `allow in on tailscale0 to any port 443 proto tcp`,
  `allow in on tailscale0 to any port 22 proto tcp`. Keep the provider's firewall closed to
  everything except, until the tailnet works, SSH from your own address. Nothing listens
  publicly: PostgreSQL and the API listen on loopback only (checked in CI), Caddy on 443 behind
  the firewall.
- **SSH:** keys only (`PasswordAuthentication no`, `PermitRootLogin no`).
- **Time:** `systemd-timesyncd` on. Tokens and login states expire by the clock.
- **Updates:** `unattended-upgrades` for security updates; reboots by hand during the rehearsal.
- **Tailscale and Caddy:** `TS_PERMIT_CERT_UID=caddy` in `/etc/default/tailscaled`, so Caddy can
  obtain the `*.ts.net` certificate from tailscaled. The name then appears in public
  Certificate Transparency logs.

## 5. Secrets and configuration (generated on the host)

Three database passwords, generated on the host and written only into the files that need them.
Hex, so no quoting is needed:

```bash
openssl rand -hex 32   # once per role: owner, operator, runtime
```

- **Owner:** used for `prisma migrate deploy` only (§6). Not stored in any file on the host; keep
  it where you keep the rehearsal's other credentials, typed into the command when needed.
- **Operator:** `/etc/ruvee/operator.env` (from `deploy/env/operator.env.example`), owner
  `ruvee-ops`, mode 0400.
- **Runtime:** `/etc/ruvee/api.env` (from `deploy/env/api.env.example`), owner root, mode 0600.
  Do not set `OPAQUE_SERVER_SETUP_FILE` there.
- **Caddy:** `/etc/ruvee/caddy.env` from `deploy/env/caddy.env.example`, with the same origin as
  `PUBLIC_ORIGIN`.
- **OPAQUE setup file,** once, as the API's user:
  `sudo -u ruvee-api node /opt/ruvee/current/apps/api/dist/admin/cli.js opaque-setup --out /etc/ruvee/api/opaque-server-setup`
  (mode 0600; it refuses to overwrite; the API refuses it in production if group or others can
  read it). Copy it offline, apart from the backups and the age
  identity (server-backup-restore.md §1).
- **Backup recipient:** made offline (§8); only the `age1…` public key goes into
  `operator.env`.

The database is named `ruvee_e2e_<8 hex>` (for example from `openssl rand -hex 4`). That name is
what keeps `ruvee-admin backup` usable for synthetic data and closed to real data.

## 6. Database: roles, migration, init, grant-runtime

In this order (database-roles.md §2, with these names):

1. As the cluster administrator (`sudo -u postgres psql`): the three roles, then `\password`
   for each, then `CREATE DATABASE ruvee_e2e_<hex> OWNER ruvee_operator` and the database
   statements of database-roles.md §2.
2. As the schema owner, from the release (the password is typed, not stored):

   ```bash
   cd /opt/ruvee/current/apps/api
   read -rs OWNER_PASSWORD
   sudo -u ruvee-ops env CHECKPOINT_DISABLE=1 \
     DATABASE_URL="postgresql://ruvee_owner:${OWNER_PASSWORD}@127.0.0.1:5432/ruvee_e2e_<hex>" \
     node_modules/.bin/prisma migrate deploy
   unset OWNER_PASSWORD
   ```

3. As the operator: `sudo -u ruvee-ops /opt/ruvee/current/deploy/bin/ruvee-admin init`
   (marks a fresh installation and grants the runtime role exactly its list).
4. After every later migration: step 2, then `… ruvee-admin grant-runtime`.
5. When you are ready to create the synthetic account: `… ruvee-admin bootstrap-token`
   (single use, 60 minutes).

## 7. Services, health, restarts, logs, disk

```bash
install -m 0644 /opt/ruvee/current/deploy/systemd/ruvee-{api,caddy,diskcheck}.service \
  /opt/ruvee/current/deploy/systemd/ruvee-diskcheck.timer /etc/systemd/system/
systemctl daemon-reload
systemctl disable --now caddy.service
systemctl enable --now ruvee-api.service ruvee-caddy.service ruvee-diskcheck.timer
```

- **Health:** `curl -fsS http://127.0.0.1:4000/health/ready` on the host (200 when the API holds
  the instance lock and reaches the database); `/health/live` for the process alone. Health
  routes are not proxied by Caddy. From a rehearsal device: `https://<host>.<tailnet>.ts.net/`.
- **Restarts:** both units restart on any exit after 5 s; ten failures in five minutes leave the
  unit failed (`systemctl --failed`). The API waits for PostgreSQL by itself and takes the lock
  again after a database restart.
- **Logs:** the journal, `journalctl -u ruvee-api -u ruvee-caddy`. Capped at 1 GB, at least 2 GB
  kept free, 30 days. The API never logs request bodies, tokens or keys.
- **Disk:** `ruvee-diskcheck.timer` checks `/`, `/var/lib/postgresql` and `/var/backups/ruvee`
  every 15 minutes; at 80 % used it logs a warning and the service fails. Nothing sends an alert
  anywhere: during the rehearsal, look at `systemctl --failed` and the journal daily.
- **Sandbox:** `systemd-analyze security ruvee-api` gives the exposure score (recorded in CI).
  The API may only use loopback (`IPAddressDeny=any`, `IPAddressAllow=localhost`).

## 8. Encrypted backups

1. **Offline, once:** `age-keygen -o ruvee-rehearsal-identity.txt` on the offline machine. Put
   the printed `age1…` into `operator.env` as `BACKUP_AGE_RECIPIENT`. The identity never
   reaches the VPS except for a restore (§9), and never the backup storage.
2. **Backup:**
   `sudo -u ruvee-ops /opt/ruvee/current/deploy/bin/ruvee-admin backup --out /var/backups/ruvee --synthetic-test-only`.
   Three files, 0600. Write the printed **backup digest** on the offline machine or on paper,
   with the date; that record is the only proof a backup is yours.
3. **Copy off the host** to the backup storage. Check each copy with `sha256sum` against the
   manifest (that finds damage, not substitution: the digest does that).
4. **Retention** for the rehearsal: keep every set until the rehearsal is closed. The guide's
   7 daily, 4 weekly, 6 monthly applies later.
5. Backups are run by hand during the rehearsal. A timer would keep the operator's database
   password on the host for unattended use; that is a later decision.

## 9. Restore into a separate, empty target, and switching to it

Follow server-backup-restore.md §4 and §5, with:

- the target `ruvee_e2e_<new hex>`, created empty as in database-roles.md §5;
- the identity copied for this run only into `/run/ruvee-restore/` (mode 0700, owner
  `ruvee-ops`) and deleted right after, and the digest from your offline record;
- `sudo -u ruvee-ops env RESTORE_DATABASE_URL=… /opt/ruvee/current/deploy/bin/ruvee-admin restore …`,
  timed (`time`), then `restore-review` and `restore-complete`.

To serve the restored database: stop `ruvee-api`, change the database name in `DATABASE_URL` in
`/etc/ruvee/api.env`, start it. The old database stays untouched until you decide otherwise (§10).

## 10. Upgrade, rollback, cleanup

- **Upgrade:** build the new commit into its own release directory (§3), take a backup (§8),
  stop the API, migrate as the owner and `grant-runtime` (§6), point `/opt/ruvee/current` at the
  new release, start the API, restart Caddy.
- **Rollback without a migration in between:** point `current` back at the previous release and
  restart both services.
- **Rollback across a migration:** migrations only go forward. Restore the backup taken before
  the upgrade into a **new** database (§9) with the previous release, and switch to it. The
  newer database stays as it is, as evidence.
- **Ending the rehearsal, keeping evidence:** first copy off the host: the journal
  (`journalctl -u ruvee-api -u ruvee-caddy -u ruvee-diskcheck -o short-iso > …`), the build
  manifests, `systemd-analyze security` output, the measurements and the restore timings. Keep
  the backup sets and the digest record until the rehearsal report is accepted. Then stop and
  disable the units, drop exactly the rehearsal databases by name and the three roles, delete
  the OPAQUE setup file and its offline copy, delete the rehearsal identity everywhere, and
  destroy the VPS. Remove the VPS and devices from the tailnet. Never reuse any of these for real
  data.

## 11. The synthetic sign-in page for autofill

On the rehearsal laptop:
`python3 -m http.server 3105 --bind 127.0.0.1 --directory deploy/rehearsal/test-site`. The
extension fills only the exact saved origin, so save the synthetic login for
`http://127.0.0.1:3105` (loopback HTTP is allowed for fill; nothing leaves the laptop).

## 12. What CI checks and what it does not

The job "Deployment rehearsal host" (`deploy/test/host-rehearsal.sh`, on `ubuntu-24.04`) does
§3 to §9 with this repository's files on a throwaway runner: the manifest comparison, PostgreSQL
`fsync`, `synchronous_commit`, `full_page_writes` and `listen_addresses`, the roles and their
order, the environment templates with no placeholder left, `systemd-analyze verify`, the API
running as `ruvee-api` on loopback, HTTPS through Caddy with HSTS, CSP and no `Server`, the
HTTP-to-HTTPS redirect, what the API user and the runtime role cannot do, a restart, a killed
API, a PostgreSQL restart, the disk check, a backup, a restore with a wrong digest (refused) and
the right one (timed), its review and completion, and the switch.

It does **not** cover: a real VPS, Tailscale and its certificate, a host reboot, the browser
flows and the extension against that host, a backup containing an account (CI's snapshot is
an initialized installation without one; the browser restore suite covers accounts on
loopback), copying to separate storage, or real time passing (log rotation, the timer, expiry).
Those are the rehearsal's acceptance criteria.
