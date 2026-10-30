#!/usr/bin/env bash
# Test-only: installs deploy/ on a disposable Ubuntu 24.04 host, as the operator would
# (docs/guides/private-rehearsal.md), and checks the host side of the rehearsal: the release build
# against the CI manifest, PostgreSQL's durability settings, the three database roles, migration,
# init and grant-runtime, the systemd units and their sandbox, Caddy over HTTPS, restarts, what the
# runtime role cannot do, an encrypted backup, a restore into a new empty database and the switch
# to it. Synthetic data only. It installs packages, creates users and starts services, so it
# refuses to run anywhere but a GitHub-hosted runner, which is discarded afterwards.
#
#   deploy/test/host-rehearsal.sh           (after a build; CI job "deploy-rehearsal")
#
# Browser flows (account setup, unlock, pairing, sync, reopening) are not here: they are the
# acceptance steps of the rehearsal itself, and the browser suites test them on loopback.
# The runner, not the command run with sudo, writes every redirected output here.
# shellcheck disable=SC2024
set -euo pipefail

if [[ "${GITHUB_ACTIONS:-}" != true || "${RUNNER_ENVIRONMENT:-}" != github-hosted ]]; then
  echo 'host-rehearsal: refusing to run outside a GitHub-hosted runner (it changes the host)' >&2
  exit 2
fi

repo=$(cd "$(dirname "$0")/../.." && pwd -P)
commit=$(git -C "$repo" rev-parse HEAD)
release=/opt/ruvee/releases/$commit
current=/opt/ruvee/current
admin=$current/deploy/bin/ruvee-admin
out=$repo/rehearsal-out
db=ruvee_e2e_$(openssl rand -hex 4)
restored=ruvee_e2e_$(openssl rand -hex 4)
wrong_target=ruvee_e2e_$(openssl rand -hex 4)
site=https://localhost
mkdir -p "$out"
failures=()

ok() { echo "ok    $*"; }
fail() {
  echo "FAIL  $*"
  failures+=("$*")
}
check() {
  local label=$1
  shift
  if "$@" >/dev/null 2>&1; then ok "$label"; else fail "$label"; fi
}
refused() {
  local label=$1
  shift
  if "$@" >/dev/null 2>&1; then fail "$label"; else ok "$label"; fi
}
step() { printf '\n== %s\n' "$*"; }
now() { date +%s.%N; }
elapsed() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.2f", b - a }'; }
as_postgres() { sudo -u postgres psql -X -q -v ON_ERROR_STOP=1 -p "$pg_port" "$@"; }
wait_for() {
  local seconds=$1
  shift
  for _ in $(seq 1 "$((seconds * 2))"); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  return 1
}
api_ready() { curl -fsS http://127.0.0.1:4000/health/ready; }
# One HTTPS request through Caddy; prints the status line and headers.
via_caddy() { curl -sS -o /dev/null -D - --cacert "$ca" "$site$1"; }
header_of() { awk -v n="$1" 'BEGIN { IGNORECASE = 1 } index(tolower($0), tolower(n) ":") == 1 { sub(/^[^:]*: */, ""); sub(/\r$/, ""); print }'; }
status_of() { awk 'NR == 1 { print $2 }'; }

# ---------------------------------------------------------------------------------------------
step 'packages: PostgreSQL 18 (PGDG), age, Caddy, Node'
for cluster in $(pg_lsclusters --no-header 2>/dev/null | awk '{ print $1 "/" $2 }'); do
  sudo pg_dropcluster --stop "${cluster%/*}" "${cluster#*/}"
done
sudo install -d /usr/share/postgresql-common/pgdg
sudo curl -fsSL -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc \
  https://www.postgresql.org/media/keys/ACCC4CF8.asc
echo 'deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt noble-pgdg main' |
  sudo tee /etc/apt/sources.list.d/pgdg.list >/dev/null
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq postgresql-18 age >/dev/null
pg_port=$(pg_lsclusters --no-header | awk '$1 == 18 && $2 == "main" { print $3 }')
[[ $pg_port == 5432 ]] || fail "PostgreSQL 18 listens on 5432 (got $pg_port)"

caddy_box=ruvee-task-caddy-bin-$(openssl rand -hex 4)
docker create --name "$caddy_box" "${RUVEE_CADDY_IMAGE:-caddy:2.11-alpine}" >/dev/null
docker cp "$caddy_box:/usr/bin/caddy" "$RUNNER_TEMP/caddy"
docker rm "$caddy_box" >/dev/null
sudo install -m 0755 "$RUNNER_TEMP/caddy" /usr/bin/caddy
sudo ln -sf "$(command -v node)" /usr/local/bin/node
{
  echo "commit $commit"
  echo "node $(node --version)"
  echo "pnpm $(pnpm --version)"
  echo "postgres $(sudo -u postgres psql -XAtq -p "$pg_port" -c 'SHOW server_version')"
  echo "caddy $(/usr/bin/caddy version)"
  echo "age $(age --version)"
  echo "systemd $(systemctl --version | head -1)"
  echo "kernel $(uname -r) $(uname -m)"
  . /etc/os-release && echo "os $PRETTY_NAME"
} | tee "$out/versions.txt"

# ---------------------------------------------------------------------------------------------
step 'release: build the commit from its tracked files, outside git, and compare manifests'
sudo install -d -o "$USER" "$release"
git -C "$repo" archive "$commit" | tar -x -C "$release"
(
  cd "$release"
  pnpm install --frozen-lockfile --prefer-offline >/dev/null
  RUVEE_BUILD_ID=$commit pnpm turbo run build --filter=@ruvee/api --filter=@ruvee/web >"$out/release-build.log" 2>&1
)
"$repo/deploy/bin/build-manifest" "$repo" >"$out/manifest-workspace.txt"
"$release/deploy/bin/build-manifest" "$release" >"$out/manifest-release.txt"
if diff -u "$out/manifest-workspace.txt" "$out/manifest-release.txt" >"$out/manifest.diff"; then
  ok "the release build matches the CI build, file for file ($(wc -l <"$out/manifest-release.txt") files)"
else
  fail "the release build differs from the CI build ($(grep -c '^+[0-9a-f]' "$out/manifest.diff") files; manifest.diff)"
fi
sudo chown -R root:root "$release"
sudo ln -sfn "$release" "$current"
# The service users cannot enter the runner's home; every path below is absolute.
cd /

# ---------------------------------------------------------------------------------------------
step 'users, directories, PostgreSQL settings, journald'
for user in ruvee-api ruvee-ops caddy; do
  id "$user" >/dev/null 2>&1 ||
    sudo useradd --system --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin "$user"
done
sudo install -d -m 0755 /etc/ruvee
sudo install -d -m 0700 /etc/ruvee/secrets
sudo install -d -m 0700 -o ruvee-ops -g ruvee-ops /var/backups/ruvee
sudo install -m 0644 "$current/deploy/postgresql/50-ruvee.conf" /etc/postgresql/18/main/conf.d/50-ruvee.conf
sudo systemctl restart postgresql@18-main
sudo install -d /etc/systemd/journald.conf.d
sudo install -m 0644 "$current/deploy/journald/50-ruvee.conf" /etc/systemd/journald.conf.d/50-ruvee.conf
sudo systemctl restart systemd-journald
for setting in fsync synchronous_commit full_page_writes; do
  value=$(sudo -u postgres psql -XAtq -p "$pg_port" -c "SHOW $setting")
  [[ $value == on ]] && ok "PostgreSQL $setting = on" || fail "PostgreSQL $setting = on (got $value)"
done
value=$(sudo -u postgres psql -XAtq -p "$pg_port" -c 'SHOW listen_addresses')
[[ $value == localhost ]] && ok 'PostgreSQL listens on localhost only' || fail "listen_addresses = $value"
check 'journald is capped (SystemMaxUse=1G)' \
  bash -c 'systemd-analyze cat-config systemd/journald.conf | grep -qx "SystemMaxUse=1G"'

# ---------------------------------------------------------------------------------------------
step 'roles, database, migration, init, grant-runtime (database-roles.md §2)'
owner_pw=$(openssl rand -hex 32)
operator_pw=$(openssl rand -hex 32)
runtime_pw=$(openssl rand -hex 32)
as_postgres -v owner_pw="$owner_pw" -v operator_pw="$operator_pw" -v runtime_pw="$runtime_pw" <<'SQL'
CREATE ROLE "ruvee_owner" LOGIN NOSUPERUSER NOCREATEDB NOREPLICATION NOBYPASSRLS NOCREATEROLE NOINHERIT;
CREATE ROLE "ruvee_operator" LOGIN NOSUPERUSER NOCREATEDB NOREPLICATION NOBYPASSRLS CREATEROLE INHERIT;
GRANT "ruvee_owner" TO "ruvee_operator" WITH INHERIT TRUE, SET TRUE;
CREATE ROLE "ruvee_runtime" LOGIN NOSUPERUSER NOCREATEDB NOREPLICATION NOBYPASSRLS NOCREATEROLE NOINHERIT;
ALTER ROLE "ruvee_owner" PASSWORD :'owner_pw';
ALTER ROLE "ruvee_operator" PASSWORD :'operator_pw';
ALTER ROLE "ruvee_runtime" PASSWORD :'runtime_pw';
SQL
new_database() {
  as_postgres -c "CREATE DATABASE \"$1\" OWNER ruvee_operator"
  as_postgres -d "$1" <<SQL
ALTER DATABASE "$1" OWNER TO "ruvee_operator";
REVOKE ALL ON DATABASE "$1" FROM PUBLIC;
GRANT CONNECT ON DATABASE "$1" TO "ruvee_owner", "ruvee_runtime";
ALTER SCHEMA public OWNER TO "ruvee_owner";
REVOKE ALL ON SCHEMA public FROM PUBLIC;
SQL
}
new_database "$db"
url() { echo "postgresql://$1:$2@127.0.0.1:$pg_port/$3"; }

identity_dir=$(mktemp -d) # stands in for the offline machine
age-keygen -o "$identity_dir/identity.txt" 2>/dev/null
recipient=$(age-keygen -y "$identity_dir/identity.txt")

sed -e "s|<operator-password>|$operator_pw|" -e "s|ruvee_e2e_<hex>|$db|" -e "s|age1<recipient>|$recipient|" \
  -e "s|:5432/|:$pg_port/|" "$current/deploy/env/operator.env.example" |
  sudo install -m 0400 -o ruvee-ops -g ruvee-ops /dev/stdin /etc/ruvee/operator.env
sed -e "s|<runtime-password>|$runtime_pw|" -e "s|ruvee_e2e_<hex>|$db|" -e "s|https://<rehearsal-host-name>|$site|" \
  -e "s|:5432/|:$pg_port/|" "$current/deploy/env/api.env.example" |
  sudo install -m 0600 /dev/stdin /etc/ruvee/api.env
sed -e "s|https://<rehearsal-host-name>|$site|" "$current/deploy/env/caddy.env.example" |
  sudo install -m 0644 /dev/stdin /etc/ruvee/caddy.env
refused 'no placeholder is left in the environment files' \
  sudo grep -lE '^[^#].*<[a-z-]+>' /etc/ruvee/api.env /etc/ruvee/caddy.env /etc/ruvee/operator.env

started=$(now)
(cd "$current/apps/api" && sudo -u ruvee-ops env DATABASE_URL="$(url ruvee_owner "$owner_pw" "$db")" \
  CHECKPOINT_DISABLE=1 PRISMA_HIDE_UPDATE_MESSAGE=1 node_modules/.bin/prisma migrate deploy >"$out/migrate.log" 2>&1) &&
  ok "migrations applied as the schema owner ($(elapsed "$started" "$(now)") s)" || fail 'prisma migrate deploy'
check 'ruvee-admin init (operator)' sudo -u ruvee-ops "$admin" init
check 'ruvee-admin grant-runtime (operator)' sudo -u ruvee-ops "$admin" grant-runtime
sudo -u ruvee-ops "$admin" bootstrap-token >"$RUNNER_TEMP/token.txt" 2>&1 &&
  grep -q 'Setup token' "$RUNNER_TEMP/token.txt" && ok 'ruvee-admin bootstrap-token (operator)' ||
  fail 'ruvee-admin bootstrap-token'
rm -f "$RUNNER_TEMP/token.txt"
sudo /usr/local/bin/node "$current/apps/api/dist/admin/cli.js" opaque-setup \
  --out /etc/ruvee/secrets/opaque-server-setup >/dev/null
[[ $(sudo stat -c %a /etc/ruvee/secrets/opaque-server-setup) == 600 ]] &&
  ok 'the OPAQUE setup file is mode 0600, in a root-only directory' || fail 'setup file mode'

# ---------------------------------------------------------------------------------------------
step 'systemd units'
for unit in ruvee-api.service ruvee-caddy.service ruvee-diskcheck.service ruvee-diskcheck.timer; do
  sudo install -m 0644 "$current/deploy/systemd/$unit" "/etc/systemd/system/$unit"
done
for unit in ruvee-api.service ruvee-caddy.service ruvee-diskcheck.service ruvee-diskcheck.timer; do
  if sudo systemd-analyze verify "/etc/systemd/system/$unit" >"$out/verify-$unit.txt" 2>&1; then
    ok "systemd-analyze verify $unit"
  else
    fail "systemd-analyze verify $unit (verify-$unit.txt)"
  fi
done
sudo systemctl daemon-reload
sudo systemctl enable --now ruvee-api.service ruvee-caddy.service ruvee-diskcheck.timer >/dev/null 2>&1
wait_for 60 api_ready && ok 'the API is ready on loopback' || fail 'the API is ready on loopback'
sudo systemd-analyze security ruvee-api.service --no-pager >"$out/security-ruvee-api.txt" 2>&1 || true
sudo systemd-analyze security ruvee-caddy.service --no-pager >"$out/security-ruvee-caddy.txt" 2>&1 || true
echo "exposure: api $(tail -1 "$out/security-ruvee-api.txt"); caddy $(tail -1 "$out/security-ruvee-caddy.txt")"

ca=$RUNNER_TEMP/caddy-root.crt
caddy_root=/var/lib/ruvee-caddy/caddy/pki/authorities/local/root.crt
wait_for 60 sudo test -s "$caddy_root" || fail 'Caddy made its local CA'
sudo cat "$caddy_root" >"$ca"
wait_for 60 curl -fsS --cacert "$ca" -o /dev/null "$site/" && ok 'Caddy serves over HTTPS' ||
  fail 'Caddy serves over HTTPS'

# ---------------------------------------------------------------------------------------------
step 'network exposure'
sudo ss -Hltn >"$out/listening.txt"
check 'the API listens on 127.0.0.1:4000 only' bash -c \
  "grep -E ':4000\b' '$out/listening.txt' | awk '{ print \$4 }' | grep -vqx '127.0.0.1:4000' && exit 1 || grep -q '127.0.0.1:4000' '$out/listening.txt'"
check 'PostgreSQL listens on loopback only' bash -c \
  "! grep -E ':$pg_port\b' '$out/listening.txt' | awk '{ print \$4 }' | grep -vqE '^(127\.0\.0\.1|\[::1\]):$pg_port$'"
api_pid=$(systemctl show -p MainPID --value ruvee-api.service)
check 'the API process runs as ruvee-api' bash -c "[[ \$(ps -o user= -p $api_pid) == ruvee-api ]]"

# ---------------------------------------------------------------------------------------------
step 'HTTPS responses through Caddy'
hsts='max-age=31536000; includeSubDomains'
for path in / /no-such-page /api/v1/account/keys; do
  case $path in
    /) want=200 ;; /no-such-page) want=404 ;; *) want=401 ;;
  esac
  response=$(via_caddy "$path")
  got=$(status_of <<<"$response")
  [[ $got == "$want" ]] && ok "$path → $want" || fail "$path → $want (got $got)"
  [[ $(header_of strict-transport-security <<<"$response") == "$hsts" ]] && ok "$path: HSTS" ||
    fail "$path: HSTS"
  [[ -n $(header_of content-security-policy <<<"$response") ]] && ok "$path: CSP" || fail "$path: CSP"
  [[ -z $(header_of server <<<"$response") ]] && ok "$path: no Server header" || fail "$path: Server header"
done
redirect=$(curl -sS -o /dev/null -w '%{http_code} %{redirect_url}' http://localhost/)
[[ $redirect == '308 https://localhost/' ]] && ok 'HTTP redirects to HTTPS' || fail "HTTP → HTTPS ($redirect)"

# ---------------------------------------------------------------------------------------------
step 'secrets and least privilege'
for file in /etc/ruvee/api.env /etc/ruvee/operator.env /etc/ruvee/secrets/opaque-server-setup; do
  refused "the API user cannot read $file" sudo -u ruvee-api cat "$file"
done
runtime_env=$RUNNER_TEMP/runtime-as-operator.env
printf 'RUVEE_ADMIN_DATABASE_URL=%s\nRUVEE_RUNTIME_ROLE=ruvee_runtime\nBACKUP_AGE_RECIPIENT=%s\nRUVEE_PG_BIN=/usr/lib/postgresql/18/bin\n' \
  "$(url ruvee_runtime "$runtime_pw" "$db")" "$recipient" | sudo install -m 0400 -o ruvee-ops /dev/stdin "$runtime_env"
for command in init grant-runtime bootstrap-token 'backup --out /var/backups/ruvee --synthetic-test-only'; do
  # shellcheck disable=SC2086
  refused "the runtime role cannot run ruvee-admin ${command%% *}" \
    sudo -u ruvee-ops env RUVEE_OPERATOR_ENV="$runtime_env" "$admin" $command
done
sudo rm -f "$runtime_env"
check 'nothing was written to the backup directory by those attempts' \
  bash -c "[[ -z \$(sudo ls -A /var/backups/ruvee) ]]"
runtime_url=$(url ruvee_runtime "$runtime_pw" "$db")
# A control first: the runtime role connects and reads what it serves, so the refusals below are
# refusals of the statement, not of the connection.
check 'the runtime role connects and reads public.accounts' \
  psql -X -q -v ON_ERROR_STOP=1 "$runtime_url" -c 'SELECT count(*) FROM public.accounts'
for sql in \
  'CREATE TABLE public.rehearsal_probe (id int)' \
  'ALTER TABLE public.accounts ADD COLUMN rehearsal_probe int' \
  'DROP TABLE public.rate_windows' \
  'TRUNCATE public.accounts' \
  'SELECT count(*) FROM public._prisma_migrations' \
  'SELECT * FROM ruvee_control.installation' \
  'UPDATE ruvee_control.installation SET origin = origin' \
  'DELETE FROM ruvee_control.installation' \
  'CREATE TABLE ruvee_control.rehearsal_probe (id int)' \
  'CREATE ROLE rehearsal_probe' \
  'CREATE SCHEMA rehearsal_probe' \
  'GRANT ALL ON public.accounts TO PUBLIC'; do
  refused "the runtime role cannot: $sql" psql -X -q -v ON_ERROR_STOP=1 "$runtime_url" -c "$sql"
done

# ---------------------------------------------------------------------------------------------
step 'restarts'
pid_before=$(systemctl show -p MainPID --value ruvee-api.service)
sudo systemctl restart ruvee-api.service
wait_for 60 api_ready && ok 'the API is ready after systemctl restart' || fail 'restart'
[[ $(systemctl show -p MainPID --value ruvee-api.service) != "$pid_before" ]] && ok 'a new process serves' ||
  fail 'a new process serves'
restarts_before=$(systemctl show -p NRestarts --value ruvee-api.service)
started=$(now)
sudo systemctl kill -s KILL ruvee-api.service
sleep 1
wait_for 60 api_ready && ok "systemd restarts a killed API ($(elapsed "$started" "$(now)") s to ready)" ||
  fail 'restart after SIGKILL'
[[ $(systemctl show -p NRestarts --value ruvee-api.service) -gt $restarts_before ]] &&
  ok 'NRestarts counted the crash' || fail 'NRestarts'
started=$(now)
sudo systemctl restart postgresql@18-main
wait_for 90 api_ready && ok "the API serves again after PostgreSQL restarted ($(elapsed "$started" "$(now)") s)" ||
  fail 'API after a PostgreSQL restart'
check 'the API still answers through Caddy' curl -fsS --cacert "$ca" -o /dev/null "$site/"

# ---------------------------------------------------------------------------------------------
step 'disk check'
check 'ruvee-diskcheck passes under a 100% threshold' env RUVEE_DISK_WARN_PERCENT=100 "$current/deploy/bin/ruvee-diskcheck"
low=$(RUVEE_DISK_WARN_PERCENT=1 "$current/deploy/bin/ruvee-diskcheck" 2>&1) && fail 'a 1% threshold fails the check' ||
  { grep -q '^<4>ruvee-diskcheck: / is' <<<"$low" && ok 'a 1% threshold fails the check with a warning' ||
    fail 'the warning line'; }
sudo systemctl start ruvee-diskcheck.service || true
check 'the timer is active' systemctl is-active --quiet ruvee-diskcheck.timer
check 'the check logs to the journal' bash -c 'journalctl -u ruvee-diskcheck.service --no-pager | grep -q "ruvee-diskcheck: / is"'

# ---------------------------------------------------------------------------------------------
step 'encrypted backup (server-backup-restore.md §3)'
started=$(now)
sudo -u ruvee-ops "$admin" backup --out /var/backups/ruvee --synthetic-test-only >"$RUNNER_TEMP/backup.txt" 2>&1 &&
  ok "backup ($(elapsed "$started" "$(now)") s)" || fail "backup: $(tail -3 "$RUNNER_TEMP/backup.txt")"
digest=$(sed -n 's/^Backup digest: \([0-9a-f]\{64\}\)$/\1/p' "$RUNNER_TEMP/backup.txt")
[[ -n $digest ]] && ok 'the backup printed its digest' || fail 'backup digest'
echo "$digest" >"$identity_dir/digest.txt" # kept with the identity, apart from backup storage
mapfile -t files < <(sudo find /var/backups/ruvee -maxdepth 1 -type f | sort)
[[ ${#files[@]} -eq 3 ]] && ok 'three files per backup' || fail "backup files: ${#files[@]}"
for file in "${files[@]}"; do
  [[ $(sudo stat -c '%a %U' "$file") == '600 ruvee-ops' ]] && ok "$(basename "$file"): 0600 ruvee-ops" ||
    fail "$(basename "$file") mode"
done
storage=$(mktemp -d) # stands in for the separate backup storage
sudo cp "${files[@]}" "$storage/" && sudo chown "$USER" "$storage"/*
manifest=$(ls "$storage"/*.manifest.json)
for kind in dump meta; do
  file=$(jq -r ".files.$kind.file" "$manifest")
  want=$(jq -r ".files.$kind.sha256" "$manifest")
  [[ $(sha256sum "$storage/$file" | cut -d' ' -f1) == "$want" ]] && ok "the stored copy of $kind matches the manifest" ||
    fail "stored copy $kind"
done

# ---------------------------------------------------------------------------------------------
step 'restore into a new, empty database (§4, §5)'
new_database "$restored"
new_database "$wrong_target"
sudo install -d -m 0700 -o ruvee-ops -g ruvee-ops /run/ruvee-restore
sudo install -m 0600 -o ruvee-ops -g ruvee-ops "$storage"/* /run/ruvee-restore/
sudo install -m 0600 -o ruvee-ops -g ruvee-ops "$identity_dir/identity.txt" /run/ruvee-restore/identity.txt
restore_manifest=/run/ruvee-restore/$(basename "$manifest")
wrong_digest=$(printf '%064d' 0)
refused 'a restore with a digest that is not the recorded one is refused' \
  sudo -u ruvee-ops env RESTORE_DATABASE_URL="$(url ruvee_operator "$operator_pw" "$wrong_target")" "$admin" restore \
  --manifest "$restore_manifest" --identity /run/ruvee-restore/identity.txt --trusted-digest "$wrong_digest"
check 'and created nothing in that target' bash -c \
  "[[ \$(sudo -u postgres psql -XAtq -p $pg_port -d $wrong_target -c \"SELECT count(*) FROM pg_tables WHERE schemaname IN ('public', 'ruvee_control')\") == 0 ]]"
restore_url=$(url ruvee_operator "$operator_pw" "$restored")
started=$(now)
if sudo -u ruvee-ops env RESTORE_DATABASE_URL="$restore_url" "$admin" restore --manifest "$restore_manifest" \
  --identity /run/ruvee-restore/identity.txt --trusted-digest "$(cat "$identity_dir/digest.txt")" >"$RUNNER_TEMP/restore.txt" 2>&1; then
  restore_seconds=$(elapsed "$started" "$(now)")
  ok "restore with the trusted digest ($restore_seconds s)"
else
  fail "restore: $(tail -3 "$RUNNER_TEMP/restore.txt")"
fi
sudo rm -rf /run/ruvee-restore
check 'the identity copy is gone from the host' bash -c '! sudo test -e /run/ruvee-restore'
restore_id=$(sed -n 's/^Restore id: \(.*\)$/\1/p' "$RUNNER_TEMP/restore.txt")
check 'restore-review' sudo -u ruvee-ops env RESTORE_DATABASE_URL="$restore_url" "$admin" restore-review
check 'restore-complete (a snapshot without an account opens)' sudo -u ruvee-ops env RESTORE_DATABASE_URL="$restore_url" \
  "$admin" restore-complete --restore-id "$restore_id" --devices-reviewed --accept-restored-credentials

step 'switch the API to the restored database'
sudo sed -i "s|/$db\$|/$restored|" /etc/ruvee/api.env
sudo systemctl restart ruvee-api.service
wait_for 60 api_ready && ok 'the API serves the restored database' || fail 'API on the restored database'
check 'the API connects to the restored database' bash -c \
  "[[ \$(sudo -u postgres psql -XAtq -p $pg_port -c \"SELECT count(*) FROM pg_stat_activity WHERE usename = 'ruvee_runtime' AND datname = '$restored'\") -gt 0 ]]"
check 'and no longer to the old one' bash -c \
  "[[ \$(sudo -u postgres psql -XAtq -p $pg_port -c \"SELECT count(*) FROM pg_stat_activity WHERE usename = 'ruvee_runtime' AND datname = '$db'\") == 0 ]]"

# ---------------------------------------------------------------------------------------------
step 'resources'
{
  for unit in ruvee-api ruvee-caddy postgresql@18-main; do
    systemctl show "$unit" -p MemoryCurrent -p MemoryPeak -p CPUUsageNSec -p TasksCurrent |
      sed "s/^/$unit /"
  done
  echo "database $db $(sudo -u postgres psql -XAtq -p "$pg_port" -c "SELECT pg_size_pretty(pg_database_size('$db'))")"
  echo "database $restored $(sudo -u postgres psql -XAtq -p "$pg_port" -c "SELECT pg_size_pretty(pg_database_size('$restored'))")"
  echo "release $(sudo du -sh "$release" | cut -f1)"
  echo "backups $(sudo du -sh /var/backups/ruvee | cut -f1)"
  echo "restore_seconds ${restore_seconds:-n/a}"
  echo "host cpus $(nproc) memory $(free -m | awk '/^Mem:/ { print $2 }') MiB"
} | tee "$out/resources.txt"
journalctl -u ruvee-api.service -u ruvee-caddy.service --no-pager >"$out/journal.txt" 2>&1 || true
sudo systemctl stop ruvee-caddy.service ruvee-api.service ruvee-diskcheck.timer
rm -rf "$identity_dir" "$storage"

if [[ ${#failures[@]} -gt 0 ]]; then
  printf '\n%s check(s) failed:\n' "${#failures[@]}"
  printf '  %s\n' "${failures[@]}"
  exit 1
fi
printf '\nAll host checks passed.\n'
