// Adaptive Security Gateway — Jenkins CI/CD
// Pipeline: Checkout -> Validate -> Build -> Unit Tests -> Smoke -> Release Gate
//           -> Docker Hub -> EC2 Deploy/Verify
// The existing production delivery path is retained; only main may publish/deploy.

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
        IMAGE_TAG = 'pending'
        DOCKER_BUILDKIT = '1'
        COMPOSE_DOCKER_CLI_BUILD = '1'

        EC2_USER = 'ubuntu'
        BASE_DIR = '/home/ubuntu/appointment-web'
        APP_DIR = '/home/ubuntu/appointment-web/Adaptive-Security-Gateway'
        ENV_PATH = '/home/ubuntu/appointment-web/.env'
        HEALTH_DOMAIN = 'asg-datn.duckdns.org'
        HEALTH_RETRIES = '12'
        COMPOSE_TIMEOUT = '120'

        ASG_CHECK_CHECKOUT = 'SKIPPED'
        ASG_CHECK_PREBUILD = 'SKIPPED'
        ASG_CHECK_BUILD = 'SKIPPED'
        ASG_CHECK_UNIT = 'SKIPPED'
        ASG_CHECK_SMOKE = 'SKIPPED'
        ASG_CHECK_RELEASE = 'SKIPPED'
        ASG_CHECK_DOCKER = 'SKIPPED'
        ASG_CHECK_DEPLOY = 'SKIPPED'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                script {
                    env.SOURCE_COMMIT = sh(script: 'git rev-parse HEAD', returnStdout: true).trim()
                    def branchSlug = (env.BRANCH_NAME ?: env.GIT_BRANCH ?: 'unknown')
                        .replaceAll('[^A-Za-z0-9_.-]', '-')
                        .take(30)

                    env.IMAGE_TAG = "ci-${branchSlug}-${env.BUILD_NUMBER}-${env.SOURCE_COMMIT.take(12)}"

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
                    for file in Jenkinsfile docker-compose.yml \
                        docappsystem/Dockerfile docappsystem/requirements.txt \
                        docappsystem/docappsystem/settings.py \
                        docappsystem/docappsystem/settings_test.py \
                        docappsystem/docappsystem/middleware.py \
                        nginx/Dockerfile nginx/nginx.conf \
                        tests/run-ci.sh; do
                        test -f "$file" || { echo "MISSING: $file" >&2; exit 1; }
                    done
                    for lua in xff_guard ip_blacklist geo_block bad_bot \
                        rate_limit rate_limit_redis waf_sqli_xss \
                        jwt_auth risk_engine utils redis_helper metrics_labels; do
                        test -f "nginx/lua/${lua}.lua" || { echo "MISSING Lua: $lua" >&2; exit 1; }
                    done
                    bash -n tests/run-ci.sh
                    git diff --check
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
                        docker tag "${GW_IMAGE}:${IMAGE_TAG}" "${GW_IMAGE}:latest"
                        docker tag "${APP_IMAGE}:${IMAGE_TAG}" "${APP_IMAGE}:latest"
                        docker push "${GW_IMAGE}:latest"
                        docker push "${APP_IMAGE}:latest"
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

log '[1] Checking production .env...'
test -f "$ENV_PATH" || fail ".env missing at $ENV_PATH"

log '[2] Fetching the exact release commit...'
mkdir -p "$BASE_DIR"
if [ ! -d "$APP_DIR/.git" ]; then
    git clone --depth 1 --branch main \
        https://github.com/NTNguyen055/Adaptive-Security-Gateway.git "$APP_DIR"
fi
cd "$APP_DIR"
PREV_COMMIT=$(git rev-parse HEAD)
git fetch origin main
FETCHED_SHA=$(git rev-parse FETCH_HEAD)
if [ "$FETCHED_SHA" != "$SOURCE_COMMIT" ]; then
    fail "EC2 main=$FETCHED_SHA differs from Jenkins image source=$SOURCE_COMMIT; refusing deploy"
fi

# Do not modify the running EC2 checkout until images are fetched and validated.
log '[3] Validating previous production images...'

# Normal deployment requires BOTH previous images.
if ! docker image inspect "${APP_IMAGE}:latest" >/dev/null 2>&1; then
    fail "Previous APP image missing: ${APP_IMAGE}:latest. Bootstrap deployment required."
fi

if ! docker image inspect "${GW_IMAGE}:latest" >/dev/null 2>&1; then
    fail "Previous GATEWAY image missing: ${GW_IMAGE}:latest. Bootstrap deployment required."
fi

# Preserve exact previous images before pulling or retagging new releases.
docker tag "${APP_IMAGE}:latest" "${APP_IMAGE}:rollback"
docker tag "${GW_IMAGE}:latest" "${GW_IMAGE}:rollback"

PREV_APP_IMAGE_ID=$(docker image inspect --format '{{.Id}}' "${APP_IMAGE}:rollback")
PREV_GW_IMAGE_ID=$(docker image inspect --format '{{.Id}}' "${GW_IMAGE}:rollback")

log '[4] Pulling release images...'
docker pull "${APP_IMAGE}:${IMAGE_TAG}"
docker pull "${GW_IMAGE}:${IMAGE_TAG}"

# Each built image must have the source revision recorded by its Dockerfile.
for spec in "${APP_IMAGE}:${IMAGE_TAG}" "${GW_IMAGE}:${IMAGE_TAG}"; do
    LABEL_SHA=$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$spec")
    [ "$LABEL_SHA" = "$SOURCE_COMMIT" ] || fail "Image source label mismatch: $spec"
done

log '[4.1] Activating verified release images...'

docker tag "${APP_IMAGE}:${IMAGE_TAG}" "${APP_IMAGE}:latest"
docker tag "${GW_IMAGE}:${IMAGE_TAG}" "${GW_IMAGE}:latest"

do_rollback() {
    log 'Rolling back previous code/images...'

    local rollback_ok=1

    docker compose --env-file "$ENV_PATH" down --remove-orphans || rollback_ok=0
    git reset --hard "$PREV_COMMIT" || rollback_ok=0

    docker image tag "${APP_IMAGE}:rollback" "${APP_IMAGE}:latest" || rollback_ok=0
    docker image tag "${GW_IMAGE}:rollback" "${GW_IMAGE}:latest" || rollback_ok=0

    # Verify that the exact previous images have been restored.
    CURRENT_APP_IMAGE_ID=$(docker image inspect --format '{{.Id}}' "${APP_IMAGE}:latest" 2>/dev/null || true)
    CURRENT_GW_IMAGE_ID=$(docker image inspect --format '{{.Id}}' "${GW_IMAGE}:latest" 2>/dev/null || true)

    [ "$CURRENT_APP_IMAGE_ID" = "$PREV_APP_IMAGE_ID" ] || rollback_ok=0
    [ "$CURRENT_GW_IMAGE_ID" = "$PREV_GW_IMAGE_ID" ] || rollback_ok=0

    if [ "$rollback_ok" -ne 1 ]; then
        log 'CRITICAL: Rollback restoration failed. Production containers will remain stopped.'
        return 1
    fi

    if ! docker compose --env-file "$ENV_PATH" up -d --wait \
        --wait-timeout "$COMPOSE_TIMEOUT" --remove-orphans; then
        log 'CRITICAL: Previous images restored but rollback startup failed.'
        return 1
    fi

    log 'Rollback completed successfully.'
}

log '[5] Switching source to the verified release commit...'
if ! git reset --hard "$SOURCE_COMMIT"; then
    do_rollback || log 'CRITICAL: Rollback incomplete; manual recovery required.'
    fail 'Cannot switch EC2 source to release commit'
fi
git clean -fd -e logs/
mkdir -p "$APP_DIR/logs/nginx"

log '[6] Starting Compose and verifying health...'
if ! docker compose --env-file "$ENV_PATH" up -d --wait \
    --wait-timeout "$COMPOSE_TIMEOUT" --remove-orphans; then
    do_rollback || log 'CRITICAL: Rollback incomplete; manual recovery required.'
    fail 'Compose deployment failed'
fi

HTTP_OK=0
HTTP_CODE="000"
HTTPS_CODE="000"

for ((i=1; i<=HEALTH_RETRIES; i++)); do
    # HTTP: kiểm tra Nginx -> Django, giữ đúng Host.
    HTTP_CODE=$(curl -sS -o /dev/null -w '%{http_code}' \
        --connect-timeout 4 --max-time 6 \
        -H "Host: $HEALTH_DOMAIN" \
        -H 'X-Forwarded-Proto: https' \
        http://127.0.0.1/health/ || true)

    # HTTPS: kiểm tra TLS, certificate hostname và Nginx -> Django.
    # --resolve giữ SNI/Host là domain production nhưng kết nối loopback.
    HTTPS_CODE=$(curl -sS -o /dev/null -w '%{http_code}' \
        --connect-timeout 4 --max-time 6 \
        --resolve "$HEALTH_DOMAIN:443:127.0.0.1" \
        "https://$HEALTH_DOMAIN/health/" || true)

    if [ "$HTTP_CODE" = "200" ] && [ "$HTTPS_CODE" = "200" ]; then
        HTTP_OK=1
        break
    fi

    log "Health check attempt $i/$HEALTH_RETRIES failed (HTTP=$HTTP_CODE, HTTPS=$HTTPS_CODE)"
    sleep 10
done

if [ "$HTTP_OK" -ne 1 ]; then
    do_rollback || log 'CRITICAL: Rollback incomplete; manual recovery required.'
    fail "HTTP/HTTPS health checks failed (http=$HTTP_CODE, https=$HTTPS_CODE)"
fi

for svc in docapp_django docapp_redis openresty_gateway; do
    STATUS=$(docker inspect --format '{{.State.Status}}' "$svc" 2>/dev/null || true)
    if [ "$STATUS" != running ]; then
        do_rollback || log 'CRITICAL: Rollback incomplete; manual recovery required.'
        fail "Container $svc is not running"
    fi
done
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
                        name: 'ASG CI / Verify Release Commit',
                        result: env.ASG_CHECK_RELEASE
                    ],
                    [
                        name: 'ASG CI / DockerHub Publish',
                        result: env.ASG_CHECK_DOCKER
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

                if [ -n "${IMAGE_TAG:-}" ] && [ "$IMAGE_TAG" != "pending" ]; then
                    docker rmi "${APP_IMAGE}:${IMAGE_TAG}" 2>/dev/null || true
                    docker rmi "${GW_IMAGE}:${IMAGE_TAG}" 2>/dev/null || true
                fi
            '''
        }
        success {
            echo "Jenkins #${BUILD_NUMBER}: CI passed. Push/Deploy stages run only for main."
        }
        failure {
            echo "Jenkins #${BUILD_NUMBER}: FAILED — ${BUILD_URL}console"
        }
    }
}
