// Adaptive Security Gateway — Jenkins CI/CD
// Pipeline: Checkout -> Validate -> Build -> Unit Regression
//           -> Smoke -> Gateway HTTPS Fault Lab
//           -> Branch-specific Publish / Release / Deploy
// Production publishing and deployment remain restricted to main.

pipeline {
    agent any

    options {
        disableConcurrentBuilds(abortPrevious: true)
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '10', artifactNumToKeepStr: '5'))
        timestamps()
    }

    environment {
        APP_IMAGE = 'ntnguyen055/adaptive-security-app'
        GW_IMAGE  = 'ntnguyen055/adaptive-security-gateway'
        DOCKER_BUILDKIT = '1'
        COMPOSE_DOCKER_CLI_BUILD = '1'

        EC2_USER = 'ubuntu'
        BASE_DIR = '/home/ubuntu/appointment-web'
        APP_DIR = '/home/ubuntu/appointment-web/Adaptive-Security-Gateway'
        ENV_PATH = '/home/ubuntu/appointment-web/.env'
        HEALTH_DOMAIN = 'asg-datn.duckdns.org'
        HEALTH_RETRIES = '12'
        COMPOSE_TIMEOUT = '120'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                script {
                    // Initialize mutable GitHub Check states.
                    env.ASG_CHECK_CHECKOUT = 'SKIPPED'
                    env.ASG_CHECK_PREBUILD = 'SKIPPED'
                    env.ASG_CHECK_BUILD = 'SKIPPED'
                    env.ASG_CHECK_UNIT = 'SKIPPED'
                    env.ASG_CHECK_SMOKE = 'SKIPPED'
                    env.ASG_CHECK_FAULT_LAB = 'SKIPPED'
                    env.FAULT_LAB_EVIDENCE = ''
                    env.ASG_CHECK_RELEASE = 'SKIPPED'
                    env.ASG_CHECK_DOCKER = 'SKIPPED'
                    env.ASG_CHECK_MIGRATION = 'SKIPPED'
                    env.ASG_CHECK_DEPLOY = 'SKIPPED'
                    env.ASG_CHECK_LATEST = 'SKIPPED'
                    env.ASG_CHECK_DEV_DOCKER = 'SKIPPED'

                    env.SOURCE_COMMIT = sh(
                        script: 'git rev-parse HEAD',
                        returnStdout: true
                    ).trim()

                    def branchSlug = (env.BRANCH_NAME ?: env.GIT_BRANCH ?: 'unknown')
                        .replaceAll('[^A-Za-z0-9_.-]', '-')
                        .take(30)

                    env.IMAGE_TAG = "ci-${branchSlug}-${env.BUILD_NUMBER}-${env.SOURCE_COMMIT.take(12)}"

                    def currentBranch = (env.BRANCH_NAME ?: env.GIT_BRANCH ?: '').trim()

                    env.DEV_IMAGE_TAG = currentBranch in [
                        'develop',
                        'origin/develop',
                        'refs/heads/develop'
                    ] ? "dev-${env.SOURCE_COMMIT.take(12)}" : ''

                    def buildSlug = env.BUILD_TAG.replaceAll('[^A-Za-z0-9_.-]', '-')
                    env.DOCKER_CONFIG = "${pwd(tmp: true)}/docker-${buildSlug}"

                    sh 'mkdir -p "$DOCKER_CONFIG"'

                    echo "Docker image tag: ${env.IMAGE_TAG}"
                }
                sh '''
                    set -eu
                    echo "Branch: ${BRANCH_NAME:-${GIT_BRANCH:-unknown}}"
                    echo "Source commit: ${SOURCE_COMMIT}"
                    git log -1 --pretty='Commit: %s'
                '''
            }
            post {
                success {
                    script { env.ASG_CHECK_CHECKOUT = 'SUCCESS' }
                }
                failure {
                    script { env.ASG_CHECK_CHECKOUT = 'FAILURE' }
                }
                unstable {
                    script { env.ASG_CHECK_CHECKOUT = 'NEUTRAL' }
                }
                aborted {
                    script { env.ASG_CHECK_CHECKOUT = 'CANCELED' }
                }
            }
        }

        stage('Pre-build Checks') {
            steps {
                sh '''
                    set -eu

                    # 1. Verify required files
                    for file in Jenkinsfile docker-compose.yml \
                        docappsystem/Dockerfile docappsystem/requirements.txt \
                        docappsystem/docappsystem/settings.py \
                        docappsystem/docappsystem/settings_test.py \
                        docappsystem/docappsystem/middleware.py \
                        nginx/Dockerfile nginx/nginx.conf \
                        tests/check-ci-suite-parity.sh \
                        tests/run-ci.sh \
                        tests/check_risk_config.py \
                        tests/test_check_risk_config.py \
                        tests/gateway_fault_lab/run_lab.py \
                        tests/gateway_fault_lab/fault_worker.lua \
                        tests/gateway_fault_lab/mock_backend.py \
                        tests/gateway_fault_lab/test_lab_helpers.py \
                        tests/test_gateway_fault_wiring.py; do
                        test -f "$file" || {
                            echo "MISSING: $file" >&2
                            exit 1
                        }
                    done

                    # 2. Verify required Lua modules
                    for lua in xff_guard ip_blacklist geo_block bad_bot \
                        rate_limit rate_limit_redis waf_sqli_xss \
                        jwt_auth risk_engine utils redis_helper metrics_labels \
                        gateway_fault_guard; do
                        test -f "nginx/lua/${lua}.lua" || {
                            echo "MISSING Lua: $lua" >&2
                            exit 1
                        }
                    done

                    # 3. Shell syntax and Lua suite parity
                    bash -n tests/run-ci.sh
                    bash -n tests/run-unit.sh
                    bash -n tests/check-ci-suite-parity.sh
                    bash tests/check-ci-suite-parity.sh

                    # 4. Verify Python runtime
                    command -v python3 >/dev/null || {
                        echo "FAIL: Python3 not found" >&2
                        exit 1
                    }

                    python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || {
                        echo "FAIL: Python >= 3.10 required" >&2
                        exit 1
                    }

                    # 5. Risk Configuration Preflight
                    python3 -m unittest discover \
                        -s tests \
                        -p 'test_check_risk_config.py' -v

                    python3 tests/check_risk_config.py \
                        --env-file .env.example

                    python3 tests/check_risk_config.py \
                        --env-file .env.local.example

                    # 6. Gateway Fault Guard Wiring
                    python3 -m unittest discover \
                        -s tests \
                        -p 'test_gateway_fault_wiring.py' -v

                    # 7. Git whitespace validation
                    git diff --check

                    # Gateway HTTPS Fault Lab preflight
                    echo 'Checking Gateway Fault Lab Python syntax...'

                    python3 -m py_compile \
                        tests/gateway_fault_lab/run_lab.py \
                        tests/gateway_fault_lab/mock_backend.py \
                        tests/gateway_fault_lab/test_lab_helpers.py

                    echo 'Running Gateway Fault Lab helper regression...'

                    python3 -m unittest discover \
                        -s tests/gateway_fault_lab \
                        -p 'test_lab_helpers.py' -v

                    echo 'Pre-build checks PASS'
                '''
            }
            post {
                success {
                    script { env.ASG_CHECK_PREBUILD = 'SUCCESS' }
                }
                failure {
                    script { env.ASG_CHECK_PREBUILD = 'FAILURE' }
                }
                unstable {
                    script { env.ASG_CHECK_PREBUILD = 'NEUTRAL' }
                }
                aborted {
                    script { env.ASG_CHECK_PREBUILD = 'CANCELED' }
                }
            }
        }

        stage('Build Images') {
            steps {
                sh '''
                    set -eu
                    BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
                    docker build --pull \
                        --cache-from "${APP_IMAGE}:latest" \
                        --build-arg BUILDKIT_INLINE_CACHE=1 \
                        --build-arg COMMIT_SHA="${SOURCE_COMMIT}" \
                        --build-arg BUILD_DATE="$BUILD_DATE" \
                        --build-arg VERSION="${IMAGE_TAG}" \
                        -t "${APP_IMAGE}:${IMAGE_TAG}" \
                        -f docappsystem/Dockerfile ./docappsystem
                    docker build --pull \
                        --cache-from "${GW_IMAGE}:latest" \
                        --build-arg BUILDKIT_INLINE_CACHE=1 \
                        --build-arg COMMIT_SHA="${SOURCE_COMMIT}" \
                        --build-arg BUILD_DATE="$BUILD_DATE" \
                        --build-arg VERSION="${IMAGE_TAG}" \
                        -t "${GW_IMAGE}:${IMAGE_TAG}" \
                        -f nginx/Dockerfile ./nginx
                '''
            }
            post {
                success {
                    script { env.ASG_CHECK_BUILD = 'SUCCESS' }
                }
                failure {
                    script { env.ASG_CHECK_BUILD = 'FAILURE' }
                }
                unstable {
                    script { env.ASG_CHECK_BUILD = 'NEUTRAL' }
                }
                aborted {
                    script { env.ASG_CHECK_BUILD = 'CANCELED' }
                }
            }
        }

        stage('Unit Regression') {
            steps {
                // Record the test output as a Jenkins build artifact.
                // Do not run the local .env.local or live Redis integration scripts here.
                sh '''
                    set -eu
                    if bash tests/run-ci.sh > ci-unit.log 2>&1; then
                        cat ci-unit.log
                    else
                        cat ci-unit.log
                        echo 'FAIL: offline regressions failed; images will not be published' >&2
                        exit 1
                    fi
                '''
            }
            post {
                success {
                    script { env.ASG_CHECK_UNIT = 'SUCCESS' }
                }
                failure {
                    script { env.ASG_CHECK_UNIT = 'FAILURE' }
                }
                unstable {
                    script { env.ASG_CHECK_UNIT = 'NEUTRAL' }
                }
                aborted {
                    script { env.ASG_CHECK_UNIT = 'CANCELED' }
                }
            }
        }

        stage('Smoke Test') {
            steps {
                sh '''
                    set -eu
                    echo 'Checking Nginx syntax on the newly built image...'
                    docker run --rm --network none \
                        --add-host docapp_django:127.0.0.1 \
                        "${GW_IMAGE}:${IMAGE_TAG}" \
                        /usr/local/openresty/bin/openresty -t
                    echo 'Checking Gateway Lua dependencies...'
                    docker run --rm --network none \
                        "${GW_IMAGE}:${IMAGE_TAG}" resty -e "
                        local libs={'resty.jwt','resty.http','resty.redis','resty.sha256','resty.string','resty.limit.req'}
                        for _,lib in ipairs(libs) do
                            assert(pcall(require,lib), 'MISSING: '..lib)
                        end
                        print('[SMOKE] Gateway Lua dependencies OK')
                    "
                '''
            }
            post {
                success {
                    script { env.ASG_CHECK_SMOKE = 'SUCCESS' }
                }
                failure {
                    script { env.ASG_CHECK_SMOKE = 'FAILURE' }
                }
                unstable {
                    script { env.ASG_CHECK_SMOKE = 'NEUTRAL' }
                }
                aborted {
                    script { env.ASG_CHECK_SMOKE = 'CANCELED' }
                }
            }
        }

        stage('Gateway HTTPS Fault Lab') {
            steps {
                script {
                    // Create a unique evidence directory for this build.
                    env.FAULT_LAB_EVIDENCE = sh(
                        script: 'mktemp -d gateway-fault-lab-results-ci-XXXXXXXX',
                        returnStdout: true
                    ).trim()
                }

                sh '''
                    set -eu

                    GW_REF="${GW_IMAGE}:${IMAGE_TAG}"
                    APP_REF="${APP_IMAGE}:${IMAGE_TAG}"

                    REDIS_REF="redis@sha256:7b1753b4c5ad8458906c272a8132b8c15f5557b000379eb115fb239706a384b7"

                    echo '=== Gateway HTTPS Fault Lab ==='
                    echo "Source commit: ${SOURCE_COMMIT}"
                    echo "Gateway image: ${GW_REF}"
                    echo "App image: ${APP_REF}"

                    printf '%s\\n' "$SOURCE_COMMIT" \
                        > "${FAULT_LAB_EVIDENCE}/source-commit.txt"

                    # Verify that both images belong to this checkout.
                    GW_REVISION="$(docker image inspect \
                        --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' \
                        "$GW_REF")"

                    APP_REVISION="$(docker image inspect \
                        --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' \
                        "$APP_REF")"

                    if [ "$GW_REVISION" != "$SOURCE_COMMIT" ] || \
                       [ "$APP_REVISION" != "$SOURCE_COMMIT" ]; then

                        echo 'FAIL: CI image revision mismatch' >&2
                        exit 1
                    fi

                    GW_ID="$(docker image inspect \
                        --format '{{.Id}}' "$GW_REF")"

                    test -n "$GW_ID"

                    echo "Gateway image ID: ${GW_ID}"

                    # The lab runner only uses existing local images.
                    # Pull the pinned Redis image if it is not cached.
                    if ! docker image inspect "$REDIS_REF" \
                        >/dev/null 2>&1; then

                        docker pull "$REDIS_REF"
                    fi

                    # Execute isolated HTTPS runtime security tests.
                    if python3 tests/gateway_fault_lab/run_lab.py \
                        --gateway-image "$GW_REF" \
                        --app-image "$APP_REF" \
                        --redis-image "$REDIS_REF" \
                        --expected-image-id "$GW_ID" \
                        --output "${FAULT_LAB_EVIDENCE}/matrix" \
                        > "${FAULT_LAB_EVIDENCE}/runner.log" 2>&1; then

                        cat "${FAULT_LAB_EVIDENCE}/runner.log"

                        test -f \
                            "${FAULT_LAB_EVIDENCE}/matrix/summary.json"

                        echo 'Gateway HTTPS Fault Lab PASS'

                    else
                        cat "${FAULT_LAB_EVIDENCE}/runner.log"

                        echo 'FAIL: Gateway HTTPS Fault Lab failed' >&2
                        echo 'Image publication and deployment are blocked' >&2

                        exit 1
                    fi
                '''
            }

            post {
                always {
                    script {
                        if (env.FAULT_LAB_EVIDENCE?.trim()) {
                            archiveArtifacts(
                                artifacts: "${env.FAULT_LAB_EVIDENCE}/**/*",
                                allowEmptyArchive: true,
                                onlyIfSuccessful: false
                            )
                        }
                    }
                }

                success {
                    script {
                        env.ASG_CHECK_FAULT_LAB = 'SUCCESS'
                    }
                }

                failure {
                    script {
                        env.ASG_CHECK_FAULT_LAB = 'FAILURE'
                    }
                }

                unstable {
                    script {
                        env.ASG_CHECK_FAULT_LAB = 'NEUTRAL'
                    }
                }

                aborted {
                    script {
                        env.ASG_CHECK_FAULT_LAB = 'CANCELED'
                    }
                }
            }
        }

        stage('Publish Develop Images') {
            when {
                expression {
                    def b = (env.BRANCH_NAME ?: env.GIT_BRANCH ?: '').trim()
                    return b in ['develop', 'origin/develop', 'refs/heads/develop']
                }
            }
            steps {
                withCredentials([usernamePassword(
                    credentialsId: 'dockerhub-cred-ASG',
                    usernameVariable: 'DOCKER_USER',
                    passwordVariable: 'DOCKER_PASS'
                )]) {
                    sh '''
                        set -eu
                        printf '%s' "$DOCKER_PASS" | docker login -u "$DOCKER_USER" --password-stdin

                        docker tag "${APP_IMAGE}:${IMAGE_TAG}" "${APP_IMAGE}:${DEV_IMAGE_TAG}"
                        docker tag "${GW_IMAGE}:${IMAGE_TAG}" "${GW_IMAGE}:${DEV_IMAGE_TAG}"

                        docker push "${APP_IMAGE}:${DEV_IMAGE_TAG}"
                        docker push "${GW_IMAGE}:${DEV_IMAGE_TAG}"

                        echo "Develop Docker Hub images published: ${DEV_IMAGE_TAG}"
                    '''
                }
            }
            post {
                success { script { env.ASG_CHECK_DEV_DOCKER = 'SUCCESS' } }
                failure { script { env.ASG_CHECK_DEV_DOCKER = 'FAILURE' } }
                unstable { script { env.ASG_CHECK_DEV_DOCKER = 'NEUTRAL' } }
                aborted { script { env.ASG_CHECK_DEV_DOCKER = 'CANCELED' } }
            }
        }

        stage('Verify Release Commit') {
            when {
                expression {
                    def b = (env.BRANCH_NAME ?: env.GIT_BRANCH ?: '').trim()
                    return b in ['main', 'origin/main', 'refs/heads/main']
                }
            }
            steps {
                sh '''
                    set -eu
                    git fetch origin main
                    REMOTE_MAIN=$(git rev-parse FETCH_HEAD)
                    if [ "$REMOTE_MAIN" != "$SOURCE_COMMIT" ]; then
                        echo 'FAIL: main moved or Jenkins built a different commit; refusing publish' >&2
                        exit 1
                    fi
                    echo "Release commit verified: $SOURCE_COMMIT"
                '''
            }
            post {
                success {
                    script { env.ASG_CHECK_RELEASE = 'SUCCESS' }
                }
                failure {
                    script { env.ASG_CHECK_RELEASE = 'FAILURE' }
                }
                unstable {
                    script { env.ASG_CHECK_RELEASE = 'NEUTRAL' }
                }
                aborted {
                    script { env.ASG_CHECK_RELEASE = 'CANCELED' }
                }
            }
        }

        stage('Push to DockerHub') {
            when {
                expression {
                    def b = (env.BRANCH_NAME ?: env.GIT_BRANCH ?: '').trim()
                    return b in ['main', 'origin/main', 'refs/heads/main']
                }
            }
            steps {
                withCredentials([usernamePassword(
                    credentialsId: 'dockerhub-cred-ASG',
                    usernameVariable: 'DOCKER_USER',
                    passwordVariable: 'DOCKER_PASS'
                )]) {
                    sh '''
                        set -eu
                        printf '%s' "$DOCKER_PASS" | docker login -u "$DOCKER_USER" --password-stdin
                        docker push "${GW_IMAGE}:${IMAGE_TAG}"
                        docker push "${APP_IMAGE}:${IMAGE_TAG}"
                    '''
                }
            }
            post {
                success {
                    script { env.ASG_CHECK_DOCKER = 'SUCCESS' }
                }
                failure {
                    script { env.ASG_CHECK_DOCKER = 'FAILURE' }
                }
                unstable {
                    script { env.ASG_CHECK_DOCKER = 'NEUTRAL' }
                }
                aborted {
                    script { env.ASG_CHECK_DOCKER = 'CANCELED' }
                }
            }
        }

        stage('Database Migration') {
            when {
                expression {
                    def b = (env.BRANCH_NAME ?: env.GIT_BRANCH ?: '').trim()
                    return b in ['main', 'origin/main', 'refs/heads/main']
                }
            }
            steps {
                script {
                    def migrationScript = '''\
#!/usr/bin/env bash
set -Eeuo pipefail

log()  { echo "[$(date '+%H:%M:%S')] $*"; }
fail() { echo "FAILED: $*" >&2; exit 1; }

log '[1] Checking production environment...'
test -f "$ENV_PATH" || fail "Production .env missing"

log '[2] Preparing application source...'
mkdir -p "$BASE_DIR"

SOURCE_WAS_PRESENT=0

if [ ! -d "$APP_DIR/.git" ]; then
    if [ -e "$APP_DIR" ]; then
        fail "APP_DIR exists but is not a Git repository: $APP_DIR"
    fi

    # Bootstrap: EC2 chưa có source production cũ.
    git clone \
        https://github.com/NTNguyen055/Adaptive-Security-Gateway.git \
        "$APP_DIR"
else
    SOURCE_WAS_PRESENT=1
fi

cd "$APP_DIR"

log '[3] Fetching and verifying release commit...'
git fetch origin main

FETCHED_SHA=$(git rev-parse FETCH_HEAD)

[ "$FETCHED_SHA" = "$SOURCE_COMMIT" ] || \
    fail "GitHub main=$FETCHED_SHA differs from Jenkins=$SOURCE_COMMIT"

log '[4] Checking out verified release source...'

PREV_COMMIT=""

if [ "$SOURCE_WAS_PRESENT" -eq 1 ]; then
    PREV_COMMIT=$(git rev-parse HEAD)
fi

git checkout --detach "$SOURCE_COMMIT"

restore_source() {
    # Lần bootstrap không có source production cũ để khôi phục.
    if [ "$SOURCE_WAS_PRESENT" -eq 0 ]; then
        return 0
    fi

    log 'Restoring previous source checkout...'

    if ! git checkout --detach "$PREV_COMMIT"; then
        log 'CRITICAL: Could not restore previous source checkout.'
        return 1
    fi
}

log 'Validating Risk Engine production config...'

if ! command -v python3 >/dev/null || \
   ! python3 "$APP_DIR/tests/check_risk_config.py" \
     --env-file "$ENV_PATH"; then

    restore_source || fail 'Source restoration failed'
    fail 'Invalid Risk Engine config; deployment rejected'
fi

log '[5] Pulling release application image...'
docker pull "${APP_IMAGE}:${IMAGE_TAG}" || {
    restore_source || fail "Image pull failed and source restoration failed"
    fail "Could not pull release application image"
}

LABEL_SHA=$(docker image inspect \
    --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' \
    "${APP_IMAGE}:${IMAGE_TAG}")

if [ "$LABEL_SHA" != "$SOURCE_COMMIT" ]; then
    restore_source || fail "Image revision mismatch and source restoration failed"
    fail "Application image revision mismatch"
fi

log '[6] Running database migration...'
export APP_IMAGE_TAG="$IMAGE_TAG"

if ! docker compose --env-file "$ENV_PATH" \
    run --rm --no-deps \
    app python manage.py migrate --noinput; then
    restore_source || fail "Migration failed and source restoration failed"
    fail "Django migration failed; database requires inspection"
fi

restore_source || fail "Migration succeeded but source restoration failed"

log "DATABASE MIGRATION SUCCESSFUL: $SOURCE_COMMIT"
'''

                    writeFile file: 'migration.sh', text: migrationScript
                }

                withCredentials([
                    string(
                        credentialsId: 'ec2-prod-ip',
                        variable: 'EC2_APP_IP'
                    ),
                    file(
                        credentialsId: 'ec2-prod-known-hosts',
                        variable: 'KNOWN_HOSTS_FILE'
                    )
                ]) {
                    sshagent(credentials: ['app-server-ssh']) {
                        sh '''
                            set -eu

                            echo "Checking pinned SSH host key..."

                            test -n "$EC2_APP_IP"
                            test -s "$KNOWN_HOSTS_FILE"

                            ssh-keygen -F "$EC2_APP_IP" \
                                -f "$KNOWN_HOSTS_FILE" >/dev/null || {
                                    echo "FAILED: No pinned SSH host key for $EC2_APP_IP" >&2
                                    exit 1
                                }

                            echo "Pinned SSH host key found."

                            ssh \
                                -o BatchMode=yes \
                                -o StrictHostKeyChecking=yes \
                                -o UpdateHostKeys=no \
                                -o UserKnownHostsFile="$KNOWN_HOSTS_FILE" \
                                -o GlobalKnownHostsFile=/dev/null \
                                -o ConnectTimeout=15 \
                                "$EC2_USER@$EC2_APP_IP" \
                                "APP_IMAGE='$APP_IMAGE' IMAGE_TAG='$IMAGE_TAG' SOURCE_COMMIT='$SOURCE_COMMIT' APP_DIR='$APP_DIR' BASE_DIR='$BASE_DIR' ENV_PATH='$ENV_PATH' bash -s" \
                                < migration.sh
                        '''
                    }
                }
            }
            post {
                success {
                    script { env.ASG_CHECK_MIGRATION = 'SUCCESS' }
                }
                failure {
                    script { env.ASG_CHECK_MIGRATION = 'FAILURE' }
                }
                unstable {
                    script { env.ASG_CHECK_MIGRATION = 'NEUTRAL' }
                }
                aborted {
                    script { env.ASG_CHECK_MIGRATION = 'CANCELED' }
                }
                always {
                    sh 'rm -f migration.sh || true'
                }
            }
        }

        stage('Deploy & Verify') {
            when {
                expression {
                    def b = (env.BRANCH_NAME ?: env.GIT_BRANCH ?: '').trim()
                    return b in ['main', 'origin/main', 'refs/heads/main']
                }
            }
            steps {
                script {
                    // Deliberately single-quoted: variables expand on the EC2 host,
                    // not inside Groovy when the deployment script is generated.
                    def deployScript = '''\
#!/usr/bin/env bash
set -Eeuo pipefail

log()  { echo "[$(date '+%H:%M:%S')] $*"; }
fail() { echo "FAILED: $*" >&2; exit 1; }

log '[1] Checking production environment...'
test -f "$ENV_PATH" || fail ".env missing at $ENV_PATH"

log '[2] Preparing and verifying source...'
mkdir -p "$BASE_DIR"

BOOTSTRAP=0

if [ ! -d "$APP_DIR/.git" ]; then
    if [ -e "$APP_DIR" ]; then
        fail "APP_DIR exists but is not a Git repository"
    fi

    BOOTSTRAP=1
    git clone --depth 1 --branch main \
        https://github.com/NTNguyen055/Adaptive-Security-Gateway.git \
        "$APP_DIR"
fi

cd "$APP_DIR"

if [ "$BOOTSTRAP" -eq 0 ]; then
    PREV_COMMIT=$(git rev-parse HEAD)
fi

git fetch origin main
FETCHED_SHA=$(git rev-parse FETCH_HEAD)

[ "$FETCHED_SHA" = "$SOURCE_COMMIT" ] || \
    fail "GitHub main=$FETCHED_SHA differs from Jenkins=$SOURCE_COMMIT"

# Strict production risk configuration gate.
# Execute the validator from the exact verified release commit.
# Reject invalid configuration before changing images or services.

log 'Validating production Risk Engine configuration...'

command -v python3 >/dev/null || \
    fail 'Python3 unavailable on EC2; cannot validate risk config'

P05_VALIDATOR_TMP="$(mktemp)" || \
    fail 'Cannot create temporary preflight file'

# Ensure cleanup on normal exit or validation failure.
trap 'rm -f -- "$P05_VALIDATOR_TMP"' EXIT

if ! git show "${SOURCE_COMMIT}:tests/check_risk_config.py" \
    > "$P05_VALIDATOR_TMP"; then

    fail 'Risk config validator missing from verified release'
fi

if ! python3 "$P05_VALIDATOR_TMP" \
    --env-file "$ENV_PATH"; then

    fail 'Invalid production Risk Engine config; deployment rejected'
fi

rm -f -- "$P05_VALIDATOR_TMP"

log 'Production Risk Engine configuration validated'

log '[3] Detecting previous production images...'

PREV_APP_IMAGE_ID=""
PREV_GW_IMAGE_ID=""

if docker image inspect "${APP_IMAGE}:latest" >/dev/null 2>&1 &&
   docker image inspect "${GW_IMAGE}:latest" >/dev/null 2>&1; then

    BOOTSTRAP=0
    PREV_APP_IMAGE_ID=$(docker image inspect --format '{{.Id}}' "${APP_IMAGE}:latest")
    PREV_GW_IMAGE_ID=$(docker image inspect --format '{{.Id}}' "${GW_IMAGE}:latest")

    docker tag "${APP_IMAGE}:latest" "${APP_IMAGE}:rollback"
    docker tag "${GW_IMAGE}:latest" "${GW_IMAGE}:rollback"

elif ! docker image inspect "${APP_IMAGE}:latest" >/dev/null 2>&1 &&
     ! docker image inspect "${GW_IMAGE}:latest" >/dev/null 2>&1; then

    BOOTSTRAP=1
    log 'BOOTSTRAP deployment: no previous production images.'

else
    fail "Only one previous production image exists; refusing unsafe deployment."
fi

log '[4] Pulling and validating release images...'

docker pull "${APP_IMAGE}:${IMAGE_TAG}"
docker pull "${GW_IMAGE}:${IMAGE_TAG}"

for spec in "${APP_IMAGE}:${IMAGE_TAG}" "${GW_IMAGE}:${IMAGE_TAG}"; do
    LABEL_SHA=$(docker image inspect \
        --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' \
        "$spec")

    [ "$LABEL_SHA" = "$SOURCE_COMMIT" ] || \
        fail "Image source label mismatch: $spec"
done

export APP_IMAGE_TAG="$IMAGE_TAG"
export GW_IMAGE_TAG="$IMAGE_TAG"

do_rollback() {
    log 'Starting rollback...'

    if [ "$BOOTSTRAP" -eq 1 ]; then
        log 'Bootstrap has no previous release; stopping new services.'
        docker compose --env-file "$ENV_PATH" down --remove-orphans || true
        return 1
    fi

    local rollback_ok=1

    docker compose --env-file "$ENV_PATH" down --remove-orphans || rollback_ok=0

    git reset --hard "$PREV_COMMIT" || rollback_ok=0
    git clean -fd -e logs/ || rollback_ok=0

    export APP_IMAGE_TAG=rollback
    export GW_IMAGE_TAG=rollback

    docker tag "${APP_IMAGE}:rollback" "${APP_IMAGE}:latest" || rollback_ok=0
    docker tag "${GW_IMAGE}:rollback" "${GW_IMAGE}:latest" || rollback_ok=0

    CURRENT_APP_IMAGE_ID=$(docker image inspect --format '{{.Id}}' "${APP_IMAGE}:rollback" 2>/dev/null || true)
    CURRENT_GW_IMAGE_ID=$(docker image inspect --format '{{.Id}}' "${GW_IMAGE}:rollback" 2>/dev/null || true)

    [ "$CURRENT_APP_IMAGE_ID" = "$PREV_APP_IMAGE_ID" ] || rollback_ok=0
    [ "$CURRENT_GW_IMAGE_ID" = "$PREV_GW_IMAGE_ID" ] || rollback_ok=0

    if [ "$rollback_ok" -ne 1 ]; then
        log 'CRITICAL: Previous release restoration failed.'
        return 1
    fi

    if ! docker compose --env-file "$ENV_PATH" up -d --wait \
        --wait-timeout "$COMPOSE_TIMEOUT" --remove-orphans; then
        log 'CRITICAL: Previous release could not restart.'
        return 1
    fi

    log 'Previous release restored.'
}

log '[5] Activating verified source...'

if ! git reset --hard "$SOURCE_COMMIT"; then
    do_rollback || log 'CRITICAL: Manual recovery required.'
    fail 'Cannot switch source to release commit'
fi

git clean -fd -e logs/
mkdir -p "$APP_DIR/logs/nginx"

log '[6] Starting production Compose...'

if ! docker compose --env-file "$ENV_PATH" up -d --wait \
    --wait-timeout "$COMPOSE_TIMEOUT" --remove-orphans; then
    do_rollback || log 'CRITICAL: Rollback incomplete; manual recovery required.'
    fail 'Compose deployment failed'
fi

log '[7] Checking HTTP and HTTPS health...'

HTTP_OK=0
HTTP_CODE="000"
HTTPS_CODE="000"

for ((i=1; i<=HEALTH_RETRIES; i++)); do
    HTTP_CODE=$(curl -sS -o /dev/null -w '%{http_code}' \
        --connect-timeout 4 --max-time 6 \
        -H "Host: $HEALTH_DOMAIN" \
        -H 'X-Forwarded-Proto: https' \
        http://127.0.0.1/health/ || true)

    HTTPS_CODE=$(curl -sS -o /dev/null -w '%{http_code}' \
        --connect-timeout 4 --max-time 6 \
        --resolve "$HEALTH_DOMAIN:443:127.0.0.1" \
        "https://$HEALTH_DOMAIN/health/" || true)

    if [ "$HTTP_CODE" = "200" ] && [ "$HTTPS_CODE" = "200" ]; then
        HTTP_OK=1
        break
    fi

    log "Health attempt $i/$HEALTH_RETRIES: HTTP=$HTTP_CODE HTTPS=$HTTPS_CODE"
    sleep 10
done

if [ "$HTTP_OK" -ne 1 ]; then
    do_rollback || log 'CRITICAL: Rollback incomplete; manual recovery required.'
    fail "Health checks failed: HTTP=$HTTP_CODE HTTPS=$HTTPS_CODE"
fi

for svc in docapp_django docapp_redis openresty_gateway; do
    STATUS=$(docker inspect --format '{{.State.Status}}' "$svc" 2>/dev/null || true)

    if [ "$STATUS" != running ]; then
        do_rollback || log 'CRITICAL: Rollback incomplete; manual recovery required.'
        fail "Container $svc is not running"
    fi
done

log '[8] Updating local production image references...'

docker tag "${APP_IMAGE}:${IMAGE_TAG}" "${APP_IMAGE}:latest"
docker tag "${GW_IMAGE}:${IMAGE_TAG}" "${GW_IMAGE}:latest"

log "DEPLOYMENT SUCCESSFUL: $SOURCE_COMMIT"
'''
                    writeFile file: 'deploy.sh', text: deployScript
                }
                withCredentials([
                    string(
                        credentialsId: 'ec2-prod-ip',
                        variable: 'EC2_APP_IP'
                    ),
                    file(
                        credentialsId: 'ec2-prod-known-hosts',
                        variable: 'KNOWN_HOSTS_FILE'
                    )
                ]) {
                    sshagent(credentials: ['app-server-ssh']) {
                        sh '''
                            set -eu

                            echo "Checking pinned SSH host key..."

                            test -n "$EC2_APP_IP"
                            test -s "$KNOWN_HOSTS_FILE"

                            ssh-keygen -F "$EC2_APP_IP" \
                                -f "$KNOWN_HOSTS_FILE" >/dev/null || {
                                    echo "FAILED: No pinned SSH host key for $EC2_APP_IP" >&2
                                    exit 1
                                }

                            echo "Pinned SSH host key found."

                            ssh \
                                -o BatchMode=yes \
                                -o StrictHostKeyChecking=yes \
                                -o UpdateHostKeys=no \
                                -o UserKnownHostsFile="$KNOWN_HOSTS_FILE" \
                                -o GlobalKnownHostsFile=/dev/null \
                                -o ConnectTimeout=15 \
                                "$EC2_USER@$EC2_APP_IP" \
                                "APP_IMAGE='$APP_IMAGE' GW_IMAGE='$GW_IMAGE' IMAGE_TAG='$IMAGE_TAG' SOURCE_COMMIT='$SOURCE_COMMIT' APP_DIR='$APP_DIR' BASE_DIR='$BASE_DIR' ENV_PATH='$ENV_PATH' HEALTH_DOMAIN='$HEALTH_DOMAIN' HEALTH_RETRIES='$HEALTH_RETRIES' COMPOSE_TIMEOUT='$COMPOSE_TIMEOUT' bash -s" < deploy.sh
                        '''
                    }
                }
            }
            post {
                success {
                    script { env.ASG_CHECK_DEPLOY = 'SUCCESS' }
                }
                failure {
                    script { env.ASG_CHECK_DEPLOY = 'FAILURE' }
                }
                unstable {
                    script { env.ASG_CHECK_DEPLOY = 'NEUTRAL' }
                }
                aborted {
                    script { env.ASG_CHECK_DEPLOY = 'CANCELED' }
                }
                always { sh 'rm -f deploy.sh || true' }
            }
        }

        stage('Publish Latest') {
            when {
                expression {
                    def b = (env.BRANCH_NAME ?: env.GIT_BRANCH ?: '').trim()
                    return b in ['main', 'origin/main', 'refs/heads/main']
                }
            }
            steps {
                withCredentials([usernamePassword(
                    credentialsId: 'dockerhub-cred-ASG',
                    usernameVariable: 'DOCKER_USER',
                    passwordVariable: 'DOCKER_PASS'
                )]) {
                    sh '''
                        set -eu

                        printf '%s' "$DOCKER_PASS" |
                            docker login -u "$DOCKER_USER" --password-stdin

                        docker tag "${APP_IMAGE}:${IMAGE_TAG}" "${APP_IMAGE}:latest"
                        docker tag "${GW_IMAGE}:${IMAGE_TAG}" "${GW_IMAGE}:latest"

                        docker push "${APP_IMAGE}:latest"
                        docker push "${GW_IMAGE}:latest"

                        echo "Docker Hub latest tags published successfully."
                    '''
                }
            }
            post {
                success {
                    script { env.ASG_CHECK_LATEST = 'SUCCESS' }
                }
                failure {
                    script { env.ASG_CHECK_LATEST = 'FAILURE' }
                }
                unstable {
                    script { env.ASG_CHECK_LATEST = 'NEUTRAL' }
                }
                aborted {
                    script { env.ASG_CHECK_LATEST = 'CANCELED' }
                }
            }
        }
    }

    post {
        always {
            script {
                def checks = [
                    [
                        name: 'ASG CI / Checkout',
                        result: env.ASG_CHECK_CHECKOUT
                    ],
                    [
                        name: 'ASG CI / Pre-build Checks',
                        result: env.ASG_CHECK_PREBUILD
                    ],
                    [
                        name: 'ASG CI / Build Images',
                        result: env.ASG_CHECK_BUILD
                    ],
                    [
                        name: 'ASG CI / Unit Regression',
                        result: env.ASG_CHECK_UNIT
                    ],
                    [
                        name: 'ASG CI / Smoke Test',
                        result: env.ASG_CHECK_SMOKE
                    ],
                    [
                        name: 'ASG CI / Gateway HTTPS Fault Lab',
                        result: env.ASG_CHECK_FAULT_LAB
                    ],
                    [
                        name: 'ASG CI / Verify Release Commit',
                        result: env.ASG_CHECK_RELEASE
                    ],
                    [
                        name: 'ASG CI / DockerHub Publish',
                        result: env.ASG_CHECK_DOCKER
                    ],
                    [
                        name: 'ASG CI / Develop DockerHub Publish',
                        result: env.ASG_CHECK_DEV_DOCKER
                    ],
                    [
                        name: 'ASG CI / Database Migration',
                        result: env.ASG_CHECK_MIGRATION
                    ],
                    [
                        name: 'ASG CI / Publish Latest',
                        result: env.ASG_CHECK_LATEST
                    ],
                    [
                        name: 'ASG CI / AWS Deploy',
                        result: env.ASG_CHECK_DEPLOY
                    ]
                ]

                checks.each { check ->
                    def result = check.result ?: 'SKIPPED'

                    def summary = result == 'SKIPPED'
                        ? 'This stage was not executed.'
                        : "Stage result: ${result}"

                    try {
                        publishChecks(
                            name: check.name,
                            status: 'COMPLETED',
                            conclusion: result,
                            title: "${check.name}: ${result}",
                            summary: summary,
                            text: """
            Branch: ${env.BRANCH_NAME ?: 'unknown'}

            Commit: ${env.SOURCE_COMMIT ?: 'not available'}

            Jenkins Build: ${env.BUILD_URL}
            """,
                            detailsURL: env.BUILD_URL
                        )
                    } catch (Exception e) {
                        echo "WARNING: Could not publish ${check.name}: ${e.message}"
                    }
                }
            }
            archiveArtifacts artifacts: 'ci-unit.log', allowEmptyArchive: true
            sh '''
                set -eu

                if [ -n "${DOCKER_CONFIG:-}" ]; then
                    docker logout >/dev/null 2>&1 || true
                    rm -rf "$DOCKER_CONFIG"
                fi

                if [ -n "${IMAGE_TAG:-}" ]; then
                    docker rmi "${APP_IMAGE}:${IMAGE_TAG}" 2>/dev/null || true
                    docker rmi "${GW_IMAGE}:${IMAGE_TAG}" 2>/dev/null || true

                    if [ -n "${DEV_IMAGE_TAG:-}" ]; then
                        docker rmi "${APP_IMAGE}:${DEV_IMAGE_TAG}" 2>/dev/null || true
                        docker rmi "${GW_IMAGE}:${DEV_IMAGE_TAG}" 2>/dev/null || true
                    fi
                fi
            '''
        }
        success {
            echo "Jenkins #${BUILD_NUMBER}: CI passed. Develop publishes dev tags. Production stages run only for main."
        }
        failure {
            echo "Jenkins #${BUILD_NUMBER}: FAILED — ${BUILD_URL}console"
        }
    }
}
