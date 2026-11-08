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
        IMAGE_TAG = "v${BUILD_NUMBER}"
        DOCKER_BUILDKIT = '1'
        COMPOSE_DOCKER_CLI_BUILD = '1'

        EC2_USER = 'ubuntu'
        BASE_DIR = '/home/ubuntu/appointment-web'
        APP_DIR = '/home/ubuntu/appointment-web/Adaptive-Security-Gateway'
        ENV_PATH = '/home/ubuntu/appointment-web/.env'
        HEALTH_DOMAIN = 'dacn3.duckdns.org'
        HEALTH_RETRIES = '12'
        COMPOSE_TIMEOUT = '120'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                script {
                    env.SOURCE_COMMIT = sh(script: 'git rev-parse HEAD', returnStdout: true).trim()
                }
                sh '''
                    set -eu
                    echo "Branch: ${BRANCH_NAME:-${GIT_BRANCH:-unknown}}"
                    echo "Source commit: ${SOURCE_COMMIT}"
                    git log -1 --pretty='Commit: %s'
                '''
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
                    credentialsId: 'dockerhub-cred-AGWS',
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
log '[3] Saving rollback tags...'
docker tag "${APP_IMAGE}:latest" "${APP_IMAGE}:rollback" 2>/dev/null || true
docker tag "${GW_IMAGE}:latest" "${GW_IMAGE}:rollback" 2>/dev/null || true

log '[4] Pulling release images...'
docker pull "${APP_IMAGE}:${IMAGE_TAG}"
docker pull "${GW_IMAGE}:${IMAGE_TAG}"
# Each built image must have the source revision recorded by its Dockerfile.
for spec in "${APP_IMAGE}:${IMAGE_TAG}" "${GW_IMAGE}:${IMAGE_TAG}"; do
    LABEL_SHA=$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$spec")
    [ "$LABEL_SHA" = "$SOURCE_COMMIT" ] || fail "Image source label mismatch: $spec"
done
docker tag "${APP_IMAGE}:${IMAGE_TAG}" "${APP_IMAGE}:latest"
docker tag "${GW_IMAGE}:${IMAGE_TAG}" "${GW_IMAGE}:latest"

do_rollback() {
    log 'Rolling back previous code/images...'
    docker compose --env-file "$ENV_PATH" down --remove-orphans || true
    git reset --hard "$PREV_COMMIT" || true
    docker tag "${APP_IMAGE}:rollback" "${APP_IMAGE}:latest" 2>/dev/null || true
    docker tag "${GW_IMAGE}:rollback" "${GW_IMAGE}:latest" 2>/dev/null || true
    docker compose --env-file "$ENV_PATH" up -d --wait \
        --wait-timeout "$COMPOSE_TIMEOUT" --remove-orphans || log 'Rollback startup failed'
}

log '[5] Switching source to the verified release commit...'
if ! git reset --hard "$SOURCE_COMMIT"; then
    do_rollback
    fail 'Cannot switch EC2 source to release commit'
fi
git clean -fd -e logs/
mkdir -p "$APP_DIR/logs/nginx"

log '[6] Starting Compose and verifying health...'
if ! docker compose --env-file "$ENV_PATH" up -d --wait \
    --wait-timeout "$COMPOSE_TIMEOUT" --remove-orphans; then
    do_rollback
    fail 'Compose deployment failed'
fi

HTTP_OK=0
for ((i=1; i<=HEALTH_RETRIES; i++)); do
    HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        -H "Host: $HEALTH_DOMAIN" -H 'X-Forwarded-Proto: https' \
        http://localhost/health/ || true)
    SEC_CODE=$(curl -k -s -o /dev/null -w '%{http_code}' \
        -A 'healthchecker' -H "Host: $HEALTH_DOMAIN" \
        https://localhost/login/ || true)
    if [ "$HTTP_CODE" = 200 ] && [ "$SEC_CODE" = 200 ]; then
        HTTP_OK=1
        break
    fi
    sleep 10
done
if [ "$HTTP_OK" -ne 1 ]; then
    do_rollback
    fail "HTTP health checks failed (http=$HTTP_CODE, login=$SEC_CODE)"
fi
for svc in docapp_django docapp_redis openresty_gateway; do
    STATUS=$(docker inspect --format '{{.State.Status}}' "$svc" 2>/dev/null || true)
    if [ "$STATUS" != running ]; then
        do_rollback
        fail "Container $svc is not running"
    fi
done
log "DEPLOYMENT SUCCESSFUL: $SOURCE_COMMIT"
'''
                    writeFile file: 'deploy.sh', text: deployScript
                }
                withCredentials([string(credentialsId: 'ec2-prod-ip', variable: 'EC2_APP_IP')]) {
                    sshagent(credentials: ['app-server-ssh']) {
                        sh '''
                            set -eu
                            mkdir -p "$HOME/.ssh"
                            chmod 700 "$HOME/.ssh"
                            if ! ssh-keygen -F "$EC2_APP_IP" >/dev/null; then
                                ssh-keyscan -H "$EC2_APP_IP" >> "$HOME/.ssh/known_hosts"
                            fi
                            chmod 644 "$HOME/.ssh/known_hosts"
                            ssh -o StrictHostKeyChecking=yes -o ConnectTimeout=15 \
                                "$EC2_USER@$EC2_APP_IP" \
                                "APP_IMAGE=$APP_IMAGE GW_IMAGE=$GW_IMAGE IMAGE_TAG=$IMAGE_TAG SOURCE_COMMIT=$SOURCE_COMMIT APP_DIR=$APP_DIR BASE_DIR=$BASE_DIR ENV_PATH=$ENV_PATH HEALTH_DOMAIN=$HEALTH_DOMAIN HEALTH_RETRIES=$HEALTH_RETRIES COMPOSE_TIMEOUT=$COMPOSE_TIMEOUT bash -s" < deploy.sh
                        '''
                    }
                }
            }
            post {
                always { sh 'rm -f deploy.sh || true' }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'ci-unit.log', allowEmptyArchive: true
            sh '''
                docker logout >/dev/null 2>&1 || true
                if [ -n "${IMAGE_TAG:-}" ]; then
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
