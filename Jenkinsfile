// =============================================================================
// Adaptive Web Security Gateway — Jenkinsfile
// Pipeline: Checkout → Lint → Build → Smoke Test → Push → Deploy → Verify
// =============================================================================

pipeline {
    agent any

    // =========================================================================
    // OPTIONS
    // =========================================================================
    options {
        disableConcurrentBuilds(abortPrevious: true)
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '10', artifactNumToKeepStr: '5'))
        timestamps()
    }

    // =========================================================================
    // ENVIRONMENT
    // =========================================================================
    environment {
        APP_IMAGE = 'ntnguyen055/api-security-app'
        GW_IMAGE  = 'ntnguyen055/api-security-gateway'
        IMAGE_TAG = "v${BUILD_NUMBER}"

        DOCKER_BUILDKIT   = '1'
        COMPOSE_DOCKER_CLI_BUILD = '1'

        DOCKERHUB_CREDS = credentials('dockerhub-cred-AGWS')
        EC2_SSH_CREDS   = 'app-server-ssh'
        
        // FIX BẢO MẬT: Lấy IP từ két sắt Jenkins, ẩn hoàn toàn khỏi Log và Source Code
        EC2_APP_IP      = credentials('ec2-prod-ip') 
        
        EC2_USER        = 'ubuntu'

        BASE_DIR        = '/home/ubuntu/appointment-web'
        APP_DIR         = '/home/ubuntu/appointment-web/API-Security-Gateway'
        ENV_PATH        = '/home/ubuntu/appointment-web/.env'

        HEALTH_DOMAIN   = 'dacn3.duckdns.org'
        HEALTH_RETRIES  = '12'
        COMPOSE_TIMEOUT = '120'
    }

    // =========================================================================
    // STAGES
    // =========================================================================
    stages {

        // ── STAGE 1: CHECKOUT ─────────────────────────────────────────────────
        stage('Checkout') {
            steps {
                echo "📥 [1/6] Checking out source code..."
                checkout scm
                sh '''
                    echo "Branch  : $(git rev-parse --abbrev-ref HEAD)"
                    echo "Commit  : $(git rev-parse HEAD)"
                    echo "Message : $(git log -1 --pretty=%s)"
                    echo "Author  : $(git log -1 --pretty=%an)"
                '''
            }
        }

        // ── STAGE 2: LINT & PRE-BUILD CHECKS ──────────────────────────────────
        stage('Lint & Pre-Build Checks') {
            steps {
                echo "🔍 [2/6] Running pre-build checks..."

                sh '''
                    echo "--- Checking required files ---"

                    test -f docappsystem/Dockerfile                || { echo "MISSING: docappsystem/Dockerfile";   exit 1; }
                    test -f docappsystem/requirements.txt           || { echo "MISSING: requirements.txt";          exit 1; }
                    test -f docappsystem/docappsystem/settings.py   || { echo "MISSING: settings.py";               exit 1; }
                    test -f docappsystem/docappsystem/middleware.py || { echo "MISSING: middleware.py";             exit 1; }
                    test -f nginx/Dockerfile                        || { echo "MISSING: nginx/Dockerfile";           exit 1; }
                    test -f nginx/nginx.conf                        || { echo "MISSING: nginx/nginx.conf";           exit 1; }
                    test -f docker-compose.yml                      || { echo "MISSING: docker-compose.yml";        exit 1; }

                    for lua in xff_guard ip_blacklist geo_block bad_bot \
                               rate_limit rate_limit_redis waf_sqli_xss \
                               jwt_auth risk_engine utils redis_helper; do
                        test -f "nginx/lua/${lua}.lua" || { echo "MISSING Lua: nginx/lua/${lua}.lua"; exit 1; }
                    done

                    if [ ! -f nginx/GeoLite2-Country.mmdb ]; then
                        echo "WARNING: nginx/GeoLite2-Country.mmdb not found. MaxMindDB lookup will not work correctly."
                    fi

                    echo "All required files present."
                '''
                // Lệnh test nginx.conf đã được dời sang Stage 4 để test trên image thực tế
            }
        }

        // ── STAGE 3: BUILD IMAGES ─────────────────────────────────────────────
        stage('Build Images') {
            steps {
                echo "🏗️  [3/6] Building Docker images..."

                sh '''
                    echo "--- Building Django App ---"
                    COMMIT_SHA=$(git rev-parse HEAD)
                    BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

                    docker build \
                        --pull \
                        --cache-from ${APP_IMAGE}:latest \
                        --build-arg BUILDKIT_INLINE_CACHE=1 \
                        --build-arg COMMIT_SHA=${COMMIT_SHA} \
                        --build-arg BUILD_DATE=${BUILD_DATE} \
                        --build-arg VERSION=${IMAGE_TAG} \
                        -t ${APP_IMAGE}:${IMAGE_TAG} \
                        -t ${APP_IMAGE}:latest \
                        -f docappsystem/Dockerfile \
                        ./docappsystem
                '''

                sh '''
                    echo "--- Building OpenResty Gateway ---"
                    COMMIT_SHA=$(git rev-parse HEAD)
                    BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

                    docker build \
                        --pull \
                        --cache-from ${GW_IMAGE}:latest \
                        --build-arg BUILDKIT_INLINE_CACHE=1 \
                        --build-arg COMMIT_SHA=${COMMIT_SHA} \
                        --build-arg BUILD_DATE=${BUILD_DATE} \
                        --build-arg VERSION=${IMAGE_TAG} \
                        -t ${GW_IMAGE}:${IMAGE_TAG} \
                        -t ${GW_IMAGE}:latest \
                        -f nginx/Dockerfile \
                        ./nginx
                '''
            }
        }

        // ── STAGE 4: SMOKE TEST ───────────────────────────────────────────────
        stage('Smoke Test') {
            steps {
                echo "🧪 [4/6] Running smoke tests..."

                // 1. Test Django
                sh '''
                    docker run --rm \
                        -e SECRET_KEY=smoke-only-not-real -e DEBUG=False \
                        -e ALLOWED_HOSTS=localhost -e DB_NAME=smoke \
                        -e DB_USER=smoke -e DB_PASSWORD=smoke -e DB_HOST=localhost \
                        -e REDIS_URL=redis://localhost:6379/1 \
                        ${APP_IMAGE}:${IMAGE_TAG} \
                        python -c "print('[SMOKE] Django image OK')"
                '''

                // 2. NÂNG CẤP: Test Nginx Syntax trực tiếp trên image vừa build (Chuẩn xác 100%)
                sh '''
                    echo "--- Validating nginx.conf syntax on built image ---"
                    # Bơm thêm host ảo để Nginx không bị lỗi phân giải DNS khi test
                    docker run --rm --add-host docapp_django:127.0.0.1 ${GW_IMAGE}:${IMAGE_TAG} /usr/local/openresty/bin/openresty -t
                    echo "[SMOKE] nginx.conf syntax OK"
                '''

                // 3. Test Lua Deps
                sh '''
                    echo "--- Gateway smoke test: Lua deps ---"
                    docker run --rm ${GW_IMAGE}:${IMAGE_TAG} resty -e "
                        local libs = {'resty.jwt', 'resty.http', 'resty.redis', 'resty.sha256', 'resty.string', 'resty.limit.req'}
                        for _, lib in ipairs(libs) do
                            assert(pcall(require, lib), 'MISSING: ' .. lib)
                        end
                        print('[SMOKE] All Gateway Lua deps OK')
                    "
                '''
            }
        }

       // ── STAGE 5: PUSH TO DOCKERHUB ────────────────────────────────────────
        stage('Push to DockerHub') {
            steps {
                script {
                    echo "--- Logging into DockerHub ---"
                    // THÊM DÒNG NÀY: Dùng pipe echo để truyền token an toàn vào lệnh login
                    sh 'echo "$DOCKERHUB_CREDS_PSW" | docker login -u "$DOCKERHUB_CREDS_USR" --password-stdin'

                    echo "--- Pushing images to DockerHub ---"
                    // 1. Push các tag version hiện tại (v144, v145...)
                    sh "docker push ${GW_IMAGE}:${IMAGE_TAG}"
                    sh "docker push ${APP_IMAGE}:${IMAGE_TAG}"
                    
                    // 2. Dán nhãn 'latest' cho bản build này và push lên mạng
                    sh "docker tag ${GW_IMAGE}:${IMAGE_TAG} ${GW_IMAGE}:latest"
                    sh "docker push ${GW_IMAGE}:latest"
                    
                    sh "docker tag ${APP_IMAGE}:${IMAGE_TAG} ${APP_IMAGE}:latest"
                    sh "docker push ${APP_IMAGE}:latest"
                }
            }
        }

        // ── STAGE 6: DEPLOY TO EC2 ────────────────────────────────────────────
        stage('Deploy & Verify') {
            steps {
                echo "🚢 [6/6] Deploying to EC2 (${EC2_APP_IP})..."

                script {
                    // FIX 8: Bỏ cơ chế replace chuỗi nguy hiểm, ghi thẳng ra file script nguyên bản
                    def deployScript = '''\
#!/usr/bin/env bash
set -euo pipefail

log()  { echo "[$(date '+%H:%M:%S')] $*"; }
fail() { echo "FAILED: $*" >&2; exit 1; }

log "[1] Validating .env file..."
test -f "${ENV_PATH}" || fail ".env not found at ${ENV_PATH}"

log "[2] Syncing code from GitHub..."
mkdir -p "${BASE_DIR}"
PREV_COMMIT="HEAD"

if [ ! -d "${APP_DIR}/.git" ]; then
    # FIX 2: Clone qua SSH (Bảo mật hơn HTTPS public)
    git clone --depth 1 git@github.com:NTNguyen055/API-Security-Gateway.git "${APP_DIR}"
else
    cd "${APP_DIR}"
    # FIX 3: Ghi chú - Lệnh sudo này yêu cầu user ubuntu được cấu hình NOPASSWD
    sudo chown -R $USER:$USER "${APP_DIR}" 2>/dev/null || true
    
    PREV_COMMIT=$(git rev-parse HEAD)
    git fetch origin --tags
    git reset --hard origin/main
    git clean -fd -e logs/
fi
cd "${APP_DIR}"

log "[3] Preparing log directories..."
mkdir -p "${APP_DIR}/logs/nginx" && chmod 755 "${APP_DIR}/logs/nginx"

log "[4] Backing up current images for rollback..."
docker tag "${APP_IMAGE}:latest" "${APP_IMAGE}:rollback" 2>/dev/null || true
docker tag "${GW_IMAGE}:latest"  "${GW_IMAGE}:rollback"  2>/dev/null || true

log "[5] Pulling new images..."
docker pull "${APP_IMAGE}:${IMAGE_TAG}" || fail "Failed to pull APP image"
docker pull "${GW_IMAGE}:${IMAGE_TAG}"  || fail "Failed to pull GW image"
docker tag "${APP_IMAGE}:${IMAGE_TAG}" "${APP_IMAGE}:latest"
docker tag "${GW_IMAGE}:${IMAGE_TAG}"  "${GW_IMAGE}:latest"

do_rollback() {
    log "Initiating rollback..."
    docker compose --env-file "${ENV_PATH}" down --remove-orphans || true
    
    # FIX 4: Rollback phục hồi lại cả mã nguồn cũ
    log "Rolling back source code to ${PREV_COMMIT}..."
    git reset --hard "${PREV_COMMIT}"
    
    docker tag "${APP_IMAGE}:rollback" "${APP_IMAGE}:latest" 2>/dev/null || true
    docker tag "${GW_IMAGE}:rollback"  "${GW_IMAGE}:latest"  2>/dev/null || true
    docker compose --env-file "${ENV_PATH}" up -d --wait --wait-timeout "${COMPOSE_TIMEOUT}" --remove-orphans || log "Rollback failed!"
}

log "[6] Deploying via docker compose..."
if ! docker compose --env-file "${ENV_PATH}" up -d --wait --wait-timeout "${COMPOSE_TIMEOUT}" --remove-orphans; then
    do_rollback
    fail "Deployment failed — rolled back"
fi

log "[7] Post-deploy HTTP health check..."
RETRY=0
HTTP_OK=0
while [ "${RETRY}" -lt "${HEALTH_RETRIES}" ]; do
    RETRY=$((RETRY + 1))
    
    HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" -H "Host: ${HEALTH_DOMAIN}" -H "X-Forwarded-Proto: https" "http://localhost/health/" || echo "000")
    
    # FIX 5: Bổ sung check qua Gateway Security Pipeline để đảm bảo file Lua không chết
    SEC_CODE=$(curl -k -s -o /dev/null -w "%{http_code}" -A "healthchecker" -H "Host: ${HEALTH_DOMAIN}" "https://localhost/login/")
    
    if [ "${HTTP_CODE}" = "200" ] && [ "${SEC_CODE}" = "200" ]; then
        HTTP_OK=1
        break
    fi
    sleep 10
done

if [ "${HTTP_OK}" -ne 1 ]; then
    do_rollback
    fail "Health checks failed (HTTP:${HTTP_CODE}, SEC:${SEC_CODE}) — rolled back"
fi

log "[8] Verifying containers..."
for svc in docapp_django docapp_redis openresty_gateway; do
    STATUS=$(docker inspect --format="{{.State.Status}}" "${svc}" 2>/dev/null || echo "missing")
    if [ "${STATUS}" != "running" ]; then
        do_rollback
        fail "Container ${svc} not running"
    fi
done

log "[9] Cleaning up old images..."
docker image prune -f
docker image prune -af --filter "until=48h" 2>/dev/null || true

log "=================================================="
log "DEPLOYMENT SUCCESSFUL"
log "=================================================="
'''
                    writeFile file: 'deploy.sh', text: deployScript
                }

                sshagent(credentials: [EC2_SSH_CREDS]) {
                    // FIX BẢO MẬT (Chuẩn TOFU): Quét và lưu Host Key tự động, từ chối kết nối nếu bị MITM
                    sh """
                        # 1. Khởi tạo thư mục SSH bảo mật cho user jenkins
                        mkdir -p ~/.ssh
                        chmod 700 ~/.ssh
                        
                        # 2. Kiểm tra xem vân tay (Host Key) của EC2 đã có trong két chưa
                        if ! ssh-keygen -F ${EC2_APP_IP} > /dev/null; then
                            echo "⚠️ Lần đầu kết nối tới ${EC2_APP_IP}. Đang quét và lưu dấu vân tay..."
                            ssh-keyscan -H ${EC2_APP_IP} >> ~/.ssh/known_hosts
                        else
                            echo "✅ Dấu vân tay của ${EC2_APP_IP} đã được xác thực an toàn trong known_hosts."
                        fi
                        chmod 644 ~/.ssh/known_hosts

                        # 3. Tiến hành SSH với chế độ bảo mật CỰC KỲ NGHIÊM NGẶT (Strict=yes)
                        ssh -o StrictHostKeyChecking=yes -o ConnectTimeout=15 ${EC2_USER}@${EC2_APP_IP} "APP_IMAGE=${APP_IMAGE} GW_IMAGE=${GW_IMAGE} IMAGE_TAG=${IMAGE_TAG} APP_DIR=${APP_DIR} BASE_DIR=${BASE_DIR} ENV_PATH=${ENV_PATH} HEALTH_DOMAIN=${HEALTH_DOMAIN} HEALTH_RETRIES=${HEALTH_RETRIES} COMPOSE_TIMEOUT=${COMPOSE_TIMEOUT} bash -s" < deploy.sh
                    """
                }
            }
            post {
                always {
                    // Xóa file tạm ở máy chạy Jenkins
                    sh 'rm -f deploy.sh || true'
                }
            }
        }
    }

    // =========================================================================
    // POST
    // =========================================================================
    post {
        always {
            echo "🧹 Cleaning up Jenkins agent..."
            sh 'docker logout || true'
            sh '''
                docker rmi ${APP_IMAGE}:${IMAGE_TAG} 2>/dev/null || true
                docker rmi ${GW_IMAGE}:${IMAGE_TAG}  2>/dev/null || true
                docker image prune -f                2>/dev/null || true
            '''
            
            script {
                def result   = currentBuild.currentResult ?: 'UNKNOWN'
                def jobName  = env.JOB_NAME
                def buildNo  = env.BUILD_NUMBER
                def buildUrl = env.BUILD_URL
                sh """
                    echo ""
                    echo "========================================"
                    echo " Build Summary"
                    echo " Job    : ${jobName}"
                    echo " Build  : #${buildNo}"
                    echo " Result : ${result}"
                    echo " URL    : ${buildUrl}"
                    echo "========================================"
                """
            }
        }
        success {
            echo "Pipeline #${BUILD_NUMBER} PASSED — ${APP_IMAGE}:${IMAGE_TAG} deployed"
            
            // [NÂNG CẤP]: Thông báo Slack khi Thành công (Màu xanh)
            // LƯU Ý: Cần cài đặt plugin "Slack Notification" trên Jenkins
            // slackSend(color: 'good', message: "✅ [SUCCESS] Triển khai thành công ${env.JOB_NAME} #${env.BUILD_NUMBER}!\nPhiên bản: ${IMAGE_TAG}\nChi tiết: ${env.BUILD_URL}")
        }
        failure {
            echo "Pipeline #${BUILD_NUMBER} FAILED — ${BUILD_URL}console"
            
            // [NÂNG CẤP]: Gửi Alert khi Thất bại (Màu đỏ)
            // Tùy chọn 1: Dùng Email (Cần cài Mailer Plugin)
            // mail to: 'devsecops-team@yourdomain.com',
            //      subject: "🚨 BÁO ĐỘNG ĐỎ: Pipeline ${env.JOB_NAME} thất bại!",
            //      body: "Pipeline ${env.JOB_NAME} [${env.BUILD_NUMBER}] đã thất bại trong quá trình build/deploy. Vui lòng kiểm tra log ngay: ${env.BUILD_URL}console"

            // Tùy chọn 2: Dùng Slack (Khuyên dùng)
            // slackSend(color: 'danger', message: "🚨 *BÁO ĐỘNG ĐỎ*: Pipeline *${env.JOB_NAME}* [#${env.BUILD_NUMBER}] đã THẤT BẠI!\nVui lòng kiểm tra ngay: ${env.BUILD_URL}console")
        }
        unstable {
            echo "Pipeline #${BUILD_NUMBER} UNSTABLE"
            // slackSend(color: 'warning', message: "⚠️ [WARNING] Pipeline ${env.JOB_NAME} [#${env.BUILD_NUMBER}] không ổn định (Unstable).")
        }
    }
}