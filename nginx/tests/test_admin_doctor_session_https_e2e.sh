#!/usr/bin/env bash
# LOCAL ONLY: authenticated Admin/Doctor session, role separation, and UI logout
# through HTTPS -> OpenResty -> Django -> local MySQL/Redis session store.
# Creates exactly two disposable local users and one disposable specialization;
# removes only those exact fixtures at exit. Never run against production.
# Does not recreate containers, change feature flags, or touch Redis keys.
set -Eeuo pipefail
export MSYS_NO_PATHCONV=1

cd "$(dirname "${BASH_SOURCE[0]}")/../.."
compose=(docker compose --env-file .env.local -f docker-compose.dev.yml)
base='https://localhost'
passed=0
workdir=''
fixture_attempted=0
fixture_ids=''
unique="$(date +%s)-${RANDOM}-${RANDOM}-$$"
admin_name="asg_role_admin_${unique//-/_}"
doctor_name="asg_role_doctor_${unique//-/_}"
admin_email="asg-role-admin-$unique@example.invalid"
doctor_email="asg-role-doctor-$unique@example.invalid"
spec_name="ASG LOCAL E2E $unique"
admin_password="ASG-Admin-E2E!${RANDOM}${RANDOM}$(date +%s)"
doctor_password="ASG-Doctor-E2E!${RANDOM}${RANDOM}$(date +%s)"

pass() { printf 'PASS  %s\n' "$1"; passed=$((passed + 1)); }
fail() { printf 'FAIL  %s\n' "$1" >&2; exit 1; }
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  set +e
  if (( fixture_attempted == 1 )); then
    "${compose[@]}" exec -T \
      -e "ASG_ROLE_ADMIN_NAME=$admin_name" \
      -e "ASG_ROLE_DOCTOR_NAME=$doctor_name" \
      -e "ASG_ROLE_ADMIN_MAIL=$admin_email" \
      -e "ASG_ROLE_DOCTOR_MAIL=$doctor_email" \
      -e "ASG_ROLE_SPEC=$spec_name" \
      -e "ASG_ROLE_IDS=$fixture_ids" \
      app python manage.py shell -c '
import os
from django.contrib.auth import get_user_model
from dasapp.models import DoctorReg, Specialization
from django.db import transaction
an=os.environ["ASG_ROLE_ADMIN_NAME"]
dn=os.environ["ASG_ROLE_DOCTOR_NAME"]
am=os.environ["ASG_ROLE_ADMIN_MAIL"]
dm=os.environ["ASG_ROLE_DOCTOR_MAIL"]
sn=os.environ["ASG_ROLE_SPEC"]
assert an.startswith("asg_role_admin_") and dn.startswith("asg_role_doctor_")
assert am.startswith("asg-role-admin-") and am.endswith("@example.invalid")
assert dm.startswith("asg-role-doctor-") and dm.endswith("@example.invalid")
assert sn.startswith("ASG LOCAL E2E ")
ids=os.environ.get("ASG_ROLE_IDS", "").split()
assert not ids or (len(ids)==3 and all(n.isdecimal() for n in ids))
User=get_user_model()
with transaction.atomic():
    for user_name,mail,role,pos in ((an,am,"1",0),(dn,dm,"2",1)):
        qs=User.objects.filter(username=user_name,email=mail,user_type=role)
        if ids: qs=qs.filter(pk=int(ids[pos]))
        assert qs.count()<=1, "Ambiguous fixture user: refusing cleanup"
        qs.delete()
    sq=Specialization.objects.filter(sname=sn)
    if ids: sq=sq.filter(pk=int(ids[2]))
    assert sq.count()<=1, "Ambiguous specialization: refusing cleanup"
    if sq.exists():
        assert not DoctorReg.objects.filter(specialization_id__in=sq).exists(), "Fixture is still in use"
        sq.delete()
print("LOCAL ADMIN/DOCTOR FIXTURES: REMOVED")
' || { echo 'CRITICAL: Fixture cleanup failed; inspect only the generated synthetic records.' >&2; rc=1; }
  fi
  if [[ -n "$workdir" && -d "$workdir" ]]; then
    rm -rf -- "$workdir" || rc=1
  fi
  if (( rc == 0 )); then
    printf '\nLOCAL ADMIN/DOCTOR HTTPS E2E: %d passed, 0 failed\n' "$passed"
  else
    printf '\nLOCAL ADMIN/DOCTOR HTTPS E2E: FAILED; check exact fixture cleanup.\n' >&2
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for cmd in docker curl grep sed awk mktemp; do
  command -v "$cmd" >/dev/null || fail "Missing prerequisite $cmd"
done
[[ -f .env.local && -f docker-compose.dev.yml ]] || fail 'Missing local Compose inputs'
port="$("${compose[@]}" port gateway 443 2>/dev/null | tr -d '\r')" || fail 'Cannot inspect local Gateway HTTPS port'
[[ "$port" == 127.0.0.1:443 ]] || fail "Refusing non-loopback Gateway HTTPS port: $port"
for service in app gateway db redis; do
  cid="$("${compose[@]}" ps -q "$service")" || fail "Cannot inspect $service"
  [[ -n "$cid" ]] || fail "Service not running: $service"
  health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing-healthcheck{{end}}' "$cid")" || fail "Cannot inspect health: $service"
  [[ "$health" == healthy ]] || fail "Unhealthy $service: $health"
done
runtime="$("${compose[@]}" exec -T app python manage.py shell -c '
import os
from django.conf import settings
ok=(os.environ.get("APP_ENV")=="local" and
    os.environ.get("DJANGO_SETTINGS_MODULE")=="docappsystem.settings_local" and
    settings.DEBUG is False and
    settings.LOGIN_ACCOUNTING_ENABLED is False and
    settings.CSRF_TRUSTED_ORIGINS==[] and
    settings.USE_X_FORWARDED_HOST is False and
    settings.USE_X_FORWARDED_PORT is False and
    settings.DATABASES["default"]["HOST"]=="db")
print("SAFE_ROLE_LAB" if ok else "UNSAFE_ROLE_LAB")
' | tr -d '\r\n')" || fail 'Cannot inspect Django runtime flags'
[[ "$runtime" == SAFE_ROLE_LAB ]] || fail 'Refusing to use unexpected Django runtime/database configuration'
pass 'Loopback HTTPS, healthy local services and safe Django settings verified'

workdir="$(mktemp -d ./.asg-role-e2e-XXXXXXXX)" || fail 'Cannot create local temporary directory'
chmod 700 "$workdir" 2>/dev/null || true
response_headers="$workdir/headers.txt"
response_body="$workdir/body.html"
admin_jar="$workdir/admin-cookies.txt"
doctor_jar="$workdir/doctor-cookies.txt"
: > "$admin_jar"
: > "$doctor_jar"
chmod 600 "$admin_jar" "$doctor_jar" 2>/dev/null || true

last_code=''
request() {
  local jar="$1" path="$2"
  shift 2
  # Do not follow redirects; do not use system HTTP proxies or production hosts.
  last_code="$(curl -k -sS --http1.1 --noproxy '*' \
    --connect-timeout 5 --max-time 15 \
    -A 'Mozilla/5.0 ASG-local-role-e2e' \
    -b "$jar" -c "$jar" -D "$response_headers" -o "$response_body" \
    -w '%{http_code}' "$@" "$base$path")" || fail "HTTPS transport error: $path"
}
expect() {
  local label="$1" status="$2" jar="$3" path="$4"
  shift 4
  request "$jar" "$path" "$@"
  [[ "$last_code" == "$status" ]] || fail "$label: expected HTTP $status, got $last_code"
  pass "$label (HTTP $status)"
}
form_csrf() {
  local result
  result="$(grep -oE 'name="csrfmiddlewaretoken"[[:space:]]+value="[^"]+"' "$response_body" \
    | sed -E 's/.*value="([^"]+)"/\1/' | sed -n '1p')" || return 1
  [[ "$result" =~ ^[A-Za-z0-9]{32,128}$ ]] || return 1
  printf '%s' "$result"
}
logout_form_csrf() {
  # Read the CSRF value strictly INSIDE the rendered logout POST form.
  # Do not substitute a token taken from a different form.
  local result
  result="$(awk '
    /<form[^>]*action="\/logout\/"[^>]*method="post"/ { inside=1; next }
    inside && /name="csrfmiddlewaretoken"/ {
      token=$0
      sub(/^.*value="/, "", token)
      sub(/".*$/, "", token)
      print token
      exit
    }
    inside && /<\/form>/ { exit }
  ' "$response_body")" || return 1
  [[ "$result" =~ ^[A-Za-z0-9]{32,128}$ ]] || return 1
  printf '%s' "$result"
}
expect_redirect() {
  local path="$1"
  grep -Eiq '^Location:[[:space:]]*/login/\?next=' "$response_headers" \
    || fail "Expected Django login redirect for $path"
}
expect_no_internal_headers() {
  if grep -Eqi '^X-Login-(Status|Accounting|Alert):' "$response_headers"; then
    fail 'Internal Login Accounting header exposed to HTTPS client'
  fi
}

# Atomic fixture creation; cleanup uses exact user IDs/names/emails/specialization.
fixture_attempted=1
fixture_ids="$("${compose[@]}" exec -T \
  -e "ASG_ROLE_ADMIN_NAME=$admin_name" \
  -e "ASG_ROLE_DOCTOR_NAME=$doctor_name" \
  -e "ASG_ROLE_ADMIN_MAIL=$admin_email" \
  -e "ASG_ROLE_DOCTOR_MAIL=$doctor_email" \
  -e "ASG_ROLE_ADMIN_PASS=$admin_password" \
  -e "ASG_ROLE_DOCTOR_PASS=$doctor_password" \
  -e "ASG_ROLE_SPEC=$spec_name" \
  app python manage.py shell -c '
import os
from django.contrib.auth import get_user_model
from dasapp.models import DoctorReg, Specialization
from django.db import transaction
an=os.environ["ASG_ROLE_ADMIN_NAME"]
dn=os.environ["ASG_ROLE_DOCTOR_NAME"]
am=os.environ["ASG_ROLE_ADMIN_MAIL"]
dm=os.environ["ASG_ROLE_DOCTOR_MAIL"]
ap=os.environ["ASG_ROLE_ADMIN_PASS"]
dp=os.environ["ASG_ROLE_DOCTOR_PASS"]
sn=os.environ["ASG_ROLE_SPEC"]
assert an.startswith("asg_role_admin_") and dn.startswith("asg_role_doctor_")
assert am.endswith("@example.invalid") and dm.endswith("@example.invalid")
assert sn.startswith("ASG LOCAL E2E ")
User=get_user_model()
with transaction.atomic():
    assert not User.objects.filter(username__in=[an,dn]).exists()
    assert not User.objects.filter(email__in=[am,dm]).exists()
    assert not Specialization.objects.filter(sname=sn).exists()
    s=Specialization.objects.create(sname=sn)
    a=User.objects.create_user(username=an,email=am,password=ap,
       user_type="1",is_active=True,is_staff=False,profile_pic="test/e2e_admin.png")
    d=User.objects.create_user(username=dn,email=dm,password=dp,
       user_type="2",is_active=True,is_staff=False,profile_pic="test/e2e_doctor.png")
    DoctorReg.objects.create(admin=d,mobilenumber="0912345678",specialization_id=s)
print(a.pk,d.pk,s.pk)
' | tr -d '\r\n')" || fail 'Cannot create disposable local Admin/Doctor fixtures'
[[ "$fixture_ids" =~ ^[1-9][0-9]*[[:space:]]+[1-9][0-9]*[[:space:]]+[1-9][0-9]*$ ]] \
  || fail 'Fixture IDs invalid; cleanup will use exact randomized names'
pass 'Disposable Admin, Doctor and DoctorReg fixture created in local DB'

# Two independent cookie jars ensure role separation is not a cookie mix-up.
run_role() {
  local role="$1" jar="$2" mail="$3" password="$4" own="$5" other="$6"
  local token logout_token
  expect "$role can open public HTTPS login" 200 "$jar" '/login/'
  token="$(form_csrf)" || fail "$role login form CSRF token missing"
  expect "$role authenticates with valid Origin and CSRF" 302 "$jar" '/doLogin/' \
    -H 'Origin: https://localhost' \
    --data-urlencode "email=$mail" \
    --data-urlencode "password=$password" \
    --data-urlencode "csrfmiddlewaretoken=$token"
  if ! grep -q $'\tsessionid\t' "$jar"; then
    fail "$role did not receive a Django sessionid cookie"
  fi
  expect_no_internal_headers
  pass "$role session cookie issued without internal header leakage"
  expect "$role own dashboard accessible" 200 "$jar" "$own"
  logout_token="$(logout_form_csrf)" || fail "$role dashboard does not contain CSRF-protected POST /logout/ form"
  pass "$role dashboard renders POST logout form with CSRF token"
  expect "$role cannot open other role dashboard" 403 "$jar" "$other"
  expect "$role forged identity headers cannot override session role" 403 "$jar" "$other" \
    -H 'X-User-ID: 1' -H 'X-User-Role: admin' \
    -H 'Authorization: Bearer forged-token'
  expect "$role non-staff custom role is denied Django Admin" 302 "$jar" '/sys-admin-panel/'
  grep -Eiq '^Location:[[:space:]]*/sys-admin-panel/login/\?next=' "$response_headers" \
    || fail "$role Django Admin did not redirect to its own login page"
  pass "$role Django Admin staff boundary preserved"
  expect "$role own session can open profile" 200 "$jar" '/profile/'
  expect "$role GET logout rejected" 405 "$jar" '/logout/'
  expect "$role GET logout preserves session" 200 "$jar" "$own"
  expect "$role POST logout without token denied" 403 "$jar" '/logout/' \
    -H 'Origin: https://localhost' --data ''
  expect "$role denied POST logout preserves session" 200 "$jar" "$own"
  expect "$role POST logout via rendered form" 302 "$jar" '/logout/' \
    -H 'Origin: https://localhost' --data-urlencode "csrfmiddlewaretoken=$logout_token"
  expect "$role logout invalidates session" 302 "$jar" "$own"
  expect_redirect "$own"
  pass "$role session redirected to login after logout"
}

run_role 'Admin' "$admin_jar" "$admin_email" "$admin_password" '/admin/' '/doctor/home/'
run_role 'Doctor' "$doctor_jar" "$doctor_email" "$doctor_password" '/doctor/home/' '/admin/'

printf '\nAll requests used https://localhost through loopback OpenResty.\n'
printf 'No production hosts, feature flags, containers or Redis keys were modified.\n'
