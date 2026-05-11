# Hệ thống Đặt lịch hẹn Bác sĩ với Adaptive Web Security Gateway

## Tổng quan

Dự án này triển khai một **Hệ thống Đặt lịch hẹn Bác sĩ** tích hợp **Adaptive Web Security Gateway** sử dụng **OpenResty** và **Lua** nhằm phòng chống tấn công Layer 7. Hệ thống được xây dựng trên nền tảng **Docker** và **Cloud**, đảm bảo bảo mật, khả năng mở rộng và dễ triển khai.

## Mục tiêu đề tài

Xây dựng một gateway bảo mật thích ứng có khả năng:
- Phát hiện và chặn các tấn công Layer 7 (SQL Injection, XSS, DDoS, Bot attacks)
- Học hỏi từ hành vi người dùng để điều chỉnh ngưỡng bảo mật
- Tích hợp liền mạch với ứng dụng web Django
- Triển khai dễ dàng trên môi trường containerized và cloud

## Kiến trúc hệ thống

```
[Client] → [OpenResty Gateway] → [Django App] → [MySQL/PostgreSQL]
              ↓                        ↓
          [Lua Modules]            [Redis Cache]
              ↓
          [Prometheus Metrics]
```

### Thành phần chính

#### 1. Django Application (`docappsystem/`)
- **Chức năng**: Hệ thống quản lý đặt lịch hẹn bác sĩ
- **Models**:
  - `CustomUser`: Người dùng (Admin, Doctor, Patient)
  - `DoctorReg`: Thông tin đăng ký bác sĩ
  - `Appointment`: Lịch hẹn
  - `Specialization`: Chuyên khoa
- **Views**: Xử lý logic nghiệp vụ đặt lịch, quản lý hồ sơ
- **Templates**: Giao diện người dùng responsive với Bootstrap 5

#### 2. OpenResty Security Gateway (`nginx/`)
- **Core**: Nginx với OpenResty để chạy Lua scripts
- **Modules Lua bảo mật**:
  - `waf_sqli_xss.lua`: Web Application Firewall chống SQLi/XSS
  - `rate_limit.lua` & `rate_limit_redis.lua`: Giới hạn tốc độ request
  - `bad_bot.lua`: Phát hiện bot độc hại
  - `geo_block.lua`: Chặn theo địa lý
  - `ip_blacklist.lua`: Danh sách đen IP
  - `xff_guard.lua`: Bảo vệ header X-Forwarded-For
  - `jwt_auth.lua`: Xác thực JWT
  - `risk_engine.lua`: Engine đánh giá rủi ro thích ứng

#### 3. Risk Engine (Adaptive Security)
- **Đánh giá rủi ro**: Tính điểm rủi ro dựa trên nhiều tín hiệu
- **Machine Learning đơn giản**: Học từ hành vi để điều chỉnh ngưỡng
- **Redis Storage**: Lưu trữ điểm uy tín IP
- **Auto-blocking**: Tự động chặn IP nguy hiểm

#### 4. Monitoring & Metrics
- **Prometheus**: Thu thập metrics bảo mật
- **Custom metrics**:
  - Số request bị chặn
  - Điểm rủi ro trung bình
  - Latency của requests

## Chức năng bảo mật

### 1. Web Application Firewall (WAF)
- Phát hiện SQL Injection với patterns nâng cao
- Chặn XSS attacks với decode HTML entities
- Quét request body, headers, URI, cookies
- Hỗ trợ JSON parsing để chống bypass

### 2. Rate Limiting
- Giới hạn request per second per IP
- Burst handling với Redis backend
- Adaptive thresholds dựa trên risk score

### 3. Bot Detection
- Phát hiện User-Agent của bots
- Phân tích hành vi request
- Chặn headless browsers và scanners

### 4. Geo-blocking
- Chặn requests từ quốc gia có rủi ro cao
- Sử dụng MaxMind GeoLite2 database
- Configurable whitelist/blacklist

### 5. IP Reputation
- Dynamic blacklist dựa trên hành vi
- Redis-backed reputation scoring
- Time-based decay và forgiveness

### 6. JWT Authentication
- Bảo vệ endpoints nhạy cảm
- Phát hiện JWT attacks (alg=none, replay)
- Integration với Django sessions

### 7. Risk-based Decision Making
- Tích hợp nhiều tín hiệu bảo mật
- Adaptive blocking/limiting
- Combo detection (SQLi + Bot = higher risk)

## Triển khai

### Yêu cầu hệ thống
- Docker & Docker Compose
- 2GB RAM minimum
- SSL certificate (Let's Encrypt)
- Redis instance
- MySQL/PostgreSQL database

### Cài đặt và chạy

1. **Clone repository**:
```bash
git clone <repository-url>
cd DAS
```

2. **Cấu hình environment**:
```bash
# Tạo file .env trong thư mục gốc
cp .env.example .env
# Chỉnh sửa các biến môi trường cần thiết
```

3. **Chạy với Docker Compose**:
```bash
# Build và start services
docker-compose up -d

# Kiểm tra logs
docker-compose logs -f
```

4. **Health check**:
```bash
curl -H "Host: dacn3.duckdns.org" https://your-domain/health/
```

### Biến môi trường quan trọng

```env
# Django
SECRET_KEY=your-secret-key
DEBUG=False
ALLOWED_HOSTS=dacn3.duckdns.org

# Database
DB_HOST=your-db-host
DB_NAME=your-db-name
DB_USER=your-db-user
DB_PASS=your-db-password

# Security Gateway
JWT_SECRET_KEY=your-jwt-secret
RATE_LIMIT_RPS=10
RISK_BLOCK_THRESHOLD=80
RISK_LIMIT_THRESHOLD=50

# Redis
REDIS_URL=redis://redis:6379/0
```

### CI/CD với Jenkins

Pipeline tự động:
1. **Checkout**: Lấy source code
2. **Lint**: Kiểm tra files cần thiết
3. **Build**: Build Docker images
4. **Test**: Smoke test cơ bản
5. **Push**: Push images lên Docker Hub
6. **Deploy**: Deploy lên EC2
7. **Verify**: Health check sau deploy

### Monitoring

- **Metrics endpoint**: `http://localhost:9145/metrics`
- **Logs**: 
  - Nginx access/error logs
  - Django application logs
  - Lua security logs

## API Endpoints

### Public Endpoints
- `GET /` - Trang chủ
- `GET /login/` - Đăng nhập
- `POST /login/` - Xử lý đăng nhập
- `GET /static/*` - Static files
- `GET /media/*` - Media files

### Protected Endpoints
- `GET /admin/` - Django admin (chỉ admin)
- `GET /doctor/*` - Chức năng bác sĩ
- `GET /user/*` - Chức năng bệnh nhân
- `POST /appointment/` - Đặt lịch hẹn

### Health Check
- `GET /health/` - Health check endpoint

## Bảo mật và Best Practices

### Defense in Depth
- **Network Layer**: Geo-blocking, IP reputation
- **Application Layer**: WAF, Input validation
- **Session Layer**: JWT validation, CSRF protection
- **Data Layer**: Parameterized queries, ORM protection

### Adaptive Security
- Risk scoring dựa trên multiple signals
- Dynamic thresholds adjustment
- Behavioral analysis

### Performance Optimization
- Lua shared dicts cho caching
- Redis backend cho persistence
- Async processing với Nginx timers

### Compliance
- GDPR compliant logging
- PCI DSS considerations
- OWASP Top 10 protection

## Phát triển và đóng góp

### Cấu trúc thư mục
```
DAS/
├── docker-compose.yml          # Orchestration
├── Jenkinsfile                 # CI/CD pipeline
├── docappsystem/               # Django application
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── manage.py
│   ├── dasapp/                 # Main app
│   └── docappsystem/           # Settings
├── nginx/                      # OpenResty gateway
│   ├── Dockerfile
│   ├── nginx.conf
│   ├── lua/                    # Security modules
│   └── GeoLite2-Country.mmdb   # Geo database
└── templates/                  # Django templates
```

### Thêm module bảo mật mới

1. Tạo file Lua trong `nginx/lua/`
2. Implement function `run(ctx)`
3. Thêm vào `nginx.conf` init_by_lua_block
4. Thêm vào security pipeline trong location blocks
5. Test và update risk_engine nếu cần

### Testing

```bash
# Unit tests Django
docker-compose exec app python manage.py test

# Security testing với OWASP ZAP
# Manual testing với curl/Postman
```

## Troubleshooting

### Common Issues

1. **Gateway không start**: Kiểm tra Lua syntax errors
2. **Redis connection failed**: Kiểm tra network trong Docker
3. **SSL certificate errors**: Verify Let's Encrypt setup
4. **High false positives**: Adjust risk thresholds

### Debug Mode

```bash
# Enable debug logging
export LUA_DEBUG=1
docker-compose up -d

# Check logs
docker-compose logs gateway
```

## Tác giả

Nguyễn Đẹp Trai - Đồ án chuyên ngành Công nghệ Thông tin

## Giấy phép

This project is licensed under the MIT License - see the LICENSE file for details.