# KẾ HOẠCH TRIỂN KHAI TỔNG THỂ ĐỒ ÁN TỐT NGHIỆP

**Đề tài:** Nghiên cứu giải pháp Adaptive Security Gateway phòng chống tấn công lớp 7 dựa trên OpenResty và Machine Learning  
**English:** Research on an Adaptive Security Gateway Solution for Defending Against Layer 7 Attacks Based on OpenResty and Machine Learning  
**Phiên bản kế hoạch:** 2.0 — cập nhật ngày 18/11/2026  
**Repository tham chiếu:** https://github.com/NTNguyen055/Adaptive-Security-Gateway  
**Nhánh đang phát triển:** `feature/p0-security-baseline` (local, tạo từ `develop`, chưa commit/push tại thời điểm cập nhật).  
**Nguyên tắc:** Chủ dự án tự sửa mã nguồn, kiểm thử, commit và merge; trợ lý chỉ đọc/review mã nguồn GitHub và đưa đề xuất.

> **Quy tắc trạng thái:** `PASS` = đã có output kiểm thử được cung cấp; `CODE` = xác nhận mã nguồn hiện diện nhưng chưa đủ bằng chứng vận hành/ nghiệm thu; `REPORTED` = đã được báo cáo từ giai đoạn trước, chưa kiểm chứng lại trong lần cập nhật này; `OPEN` = chưa nghiệm thu; `PLANNED` = định hướng chưa triển khai. Không đồng nhất có code với đã PASS.

## I. TÓM TẮT ĐIỀU HÀNH VÀ MỤC TIÊU NGHIÊN CỨU

Kế hoạch **giữ 4 giai đoạn lớn của tài liệu gốc (29/10/2026)**: (1) hoàn thiện nền tảng bảo mật, (2) triển khai/vận hành AWS, (3) nghiên cứu và tích hợp Machine Learning, (4) thực nghiệm và hoàn thiện luận văn. Để dễ quản lý khối lượng còn lại, các việc được triển khai qua **6 workstream P0–P5**; đây là cách chia tiến độ, **không thay thế** cấu trúc 4 giai đoạn gốc.

**Mục tiêu cuối cùng:** xây dựng và đánh giá một Gateway lớp 7 có khả năng (i) phòng vệ rule-based ổn định trên OpenResty, (ii) phát hiện hành vi bất thường bằng ML đã huấn luyện, (iii) đưa ra phản ứng thích ứng có trạng thái và giới hạn an toàn, (iv) chứng minh hiệu quả, chi phí và khả năng chịu lỗi bằng thực nghiệm có thể tái lập.

**Ba câu hỏi nghiên cứu:**

- **RQ1 — Hiệu quả phát hiện:** Kết hợp Machine Learning có cải thiện Recall/F1 với HTTP Flood và hành vi bot-like so với Rule-Based Gateway hay không, và đánh đổi FPR là bao nhiêu?
- **RQ2 — Giá trị Adaptive:** Với cùng mô hình ML, chính sách phản ứng thích ứng theo hành vi/risk history có cải thiện thời gian giảm thiểu tấn công, khả năng phục hồi và false positive đối với legitimate burst so với quyết định tĩnh hay không?
- **RQ3 — Tính khả thi thực tế:** Chi phí p95/p99 latency, throughput, CPU/RAM/Redis và hành vi fallback khi Redis/ML lỗi có chấp nhận được không?

**Nguyên tắc thiết kế:** Rule-Based luôn là lớp bảo vệ độc lập; ML không được trở thành single point of failure; không sử dụng dữ liệu bệnh nhân thật hoặc token/cookie/password trong dataset/log; không thử flooding gây gián đoạn trên production.

### I.1. Bản đồ 4 giai đoạn và 6 workstream

| Giai đoạn gốc | Workstream | Trọng tâm | Trạng thái 18/11/2026 |
|---|---|---|---|
| GĐ1 — Rule-Based Security Baseline | **P0** | Hoàn thiện authorization, brute-force, CSRF, CI, Risk/TTL, WAF/privacy, benchmark | **Đang thực hiện; chưa đóng Baseline Ready** |
| GĐ2 — AWS Deployment & Operations | **P1** | Rà soát tình trạng triển khai, recovery, rollback, monitoring, chi phí | **Nền tảng có mã và có báo cáo vận hành; cần nghiệm thu chọn lọc** |
| GĐ3 — ML Research & Hybrid | **P2 + P3 + P4** | Dataset/feature → training → inference + Adaptive Decision | **PLANNED; chưa có bằng chứng triển khai hoàn chỉnh** |
| GĐ4 — Experiments & Thesis | **P5** | E1–E5; A–D + ablation; báo cáo/slide/demo | **PLANNED; có thiết kế kịch bản, chưa có kết quả cuối** |

### I.2. Mốc bắt buộc

1. **Baseline Ready:** P0.1–P0.8 đạt điều kiện nghiệm thu, có test report, cấu hình được phiên bản hóa và benchmark Rule-Based.
2. **ML Model Ready:** Dataset và schema tái lập; một mô hình được huấn luyện, đánh giá trên test độc lập và đóng gói có version.
3. **Hybrid Ready:** OpenResty nhận ML signal; chế độ `off/shadow/enforce`; Adaptive Decision và fallback có test.
4. **Research Validated:** Có số liệu A–D và đối chứng *ML có/không có Adaptive*; đồ thị, phân tích giới hạn, luận văn và demo.

## II. ĐÁNH GIÁ TIẾN ĐỘ THỰC TẾ (CHỐT NGÀY 18/11/2026)

### II.1. Thành phần đã có và bằng chứng

| Nhóm | Nội dung đã thực hiện hoặc có cơ sở | Trạng thái và nguồn bằng chứng |
|---|---|---|
| Local development | `docker-compose.dev.yml`, `.env.local`, MySQL/Redis/Django/OpenResty local; tách dev và production; health checks | **PASS được báo cáo**: Django và Gateway healthy ngày 18/11; tài liệu local và Compose hiện diện |
| Authorization P0.1 | Bảo vệ `PROFILE`/`CHANGE_PASSWORD`; PasswordChangeForm; update session hash; `PROFILE_UPDATE` POST-only; template; 8 authorization tests; sửa test cũ | **PASS:** 8/8 P0.1 tests và 84/84 Django regressions (18/11) |
| P0.1 HTTP access | Anonymous `/profile/`, `/password/` chuyển HTTP 302 tới `/login/` | **PASS được báo cáo** qua `curl` local ngày 18/11; Admin/Doctor manual flow chưa xác nhận riêng |
| P0.2.1 Login Security Signal | Test `@require_POST`, wrong/unknown/inactive credentials, Admin/Doctor success, CSRF no-login-signal | **PASS:** sau khi thêm 7 tests, **91/91 Django tests, 19.981 giây, OK** (output user cung cấp) |
| Lua rule-based | Redis rate limiting, IP blacklist, WAF, JWT, risk scoring, brute-force, monitoring có mã nguồn | **CODE** trên nhánh GitHub `develop`; chưa thay thế bằng bằng chứng P0 cuối |
| Lua historical test | 97/97 Lua tests và 17/17 Django isolated tests ngày 17/11/2026 | **REPORTED** từ bản rà soát trước; không cộng hoặc nhập nhằng với 91 Django tests hiện tại |
| Jenkins / DockerHub | Pipeline build/test/push/deploy, nhánh develop/main, các smoke checks và rollback path | **CODE + REPORTED:** CI `main` success ở lần review trước; chưa chứng minh recovery/rollback thực tế hoặc CI cho P0 mới |
| AWS / RDS / S3 / TLS | Cấu hình EC2, RDS MySQL TLS verification, S3 private media, HTTPS, monitoring đã có trong tài liệu/repo | **CODE + REPORTED:** hoạt động triển khai trước đây; cần kiểm chứng dịch vụ và recovery hiện tại, không coi hoàn thành P1 |
| ML / Adaptive Threshold / Z-score Baseline | Trong mã OpenResty `develop` chưa tìm thấy triển khai đầy đủ `ADAPTIVE_*` hoặc `BASELINE_*`; ML pipeline/inference chưa nghiệm thu | **PLANNED**, không được báo cáo là đang chạy chỉ vì `.env` có biến |

**Lưu ý về mốc lịch sử:** Kế hoạch gốc ngày 29/10/2026 mô tả AWS cần khôi phục sau khi tài nguyên cũ bị gỡ; các tài liệu và báo cáo cập nhật gần 18/11 cho thấy cấu hình triển khai/CI đã tiến xa hơn. Bản này lấy **bằng chứng mới nhất** làm trạng thái làm việc nhưng vẫn yêu cầu kiểm chứng lại vận hành AWS trước khi đóng P1.

### II.2. Các việc CHƯA được phép đánh dấu PASS

- **P0.2.2** patch OpenResty `/login/`, `/doLogin/` và loại bỏ header `X-Login-Status` ra client **đã được hướng dẫn nhưng chưa có kết quả `openresty -t`, HTTP/Redis integration được gửi**. Không mặc định đã sửa trên local.
- **P0.2.3–P0.2.4** Redis counter, cooldown, concurrency và shared IP chưa có báo cáo PASS cho feature branch.
- **P0.3–P0.8** vẫn mở. Riêng bộ 91 Django tests PASS không đồng nghĩa Jenkins đã tích hợp đầy đủ regression hoặc Security Baseline đã được chốt.
- Phần ML Training/Inference và Adaptive Decision Engine/Z-score chưa có mã hoàn chỉnh và không có metrics thực nghiệm cuối.

## III. GIAI ĐOẠN 1 — P0: HOÀN TẤT SECURITY BASELINE

**Mục tiêu:** chốt phiên bản Rule-Based Gateway chính xác, có thể lặp lại, không gây hồi quy Django và có dữ liệu đo baseline phục vụ so sánh ML. **Ưu tiên hiện tại: P0.2.** Không chuyển sang P0.3 khi P0.2 chưa PASS.

| Mã | Nội dung, file/trọng điểm | Trạng thái | Điều kiện nghiệm thu cụ thể |
|---|---|---|---|
| **P0.1** | Authorization: `views.py`, templates, `test_profile_authorization.py`, regression Django | **PASS** | 8/8 P0.1, 84/84 regression ban đầu; 302 anonymous theo báo cáo; manual Admin/Doctor ghi riêng nếu còn thiếu |
| **P0.2.1** | Django login status contract: `@require_POST`, `X-Login-Status`, 7 tests | **PASS** | 91/91 Django regressions (18/11) |
| **P0.2.2** | `nginx/nginx.conf`: exact locations; POST-only signal, không lộ internal header | **OPEN** | `openresty -t` PASS, gateway healthy, HTTP 405/403/302 đúng, header ẩn và Redis counter ghi đúng |
| **P0.2.3** | `nginx/lua/brute_force_login.lua` và Lua tests: atomic `INCR+TTL`, threshold/cooldown, fallback | **OPEN** | Tăng đúng 1/lần failed login; threshold=5, window=300s, cooldown=3600s theo cấu hình; Redis fail test PASS |
| **P0.2.4** | Live integration: Redis thực, concurrent requests, shared NAT/IP và recovery | **OPEN** | IP khóa/khôi phục đúng, không mất lần đếm trong bài test chấp nhận, chính sách shared IP và race condition được tài liệu hóa |
| **P0.3** | CSRF: POST endpoints, Android/clients, auth + method | **OPEN** | CSRF negative/positive, tác động Android tái hiện hoặc loại trừ có bằng chứng |
| **P0.4** | `dasapp.tests` trong Jenkins CI; Django/Lua/gateway smoke; artifact report | **OPEN** | CI trên commit mới chạy đầy đủ các nhóm test bắt buộc và lưu log |
| **P0.5** | Risk weights, TTL, temporary ban, reputation/decay, Redis authority | **OPEN** | Quy tắc thang 0–100, TTL nhất quán, test shared IP/decay/ban-unban PASS |
| **P0.6** | WAF SQLi/XSS false positives; log privacy / không có secrets hoặc PII | **OPEN** | Controlled benign/attack cases và audit logs có báo cáo |
| **P0.7** | Traffic benchmark Rule-Based local (normal/burst/flood an toàn) | **OPEN** | Raw results + p50/p95/p99, RPS, CPU/RAM, tỷ lệ block/false positive có nhãn |
| **P0.8** | Baseline version, test matrix, chính sách bảo mật, tài liệu và tag | **OPEN** | Có commit/tag, config snapshot không secrets, test & benchmark reports, checklist Baseline Ready |

### III.1. P0.2 — Chuỗi kiểm thử đang thực hiện

**Luồng:** Client `POST /doLogin/` → OpenResty `check_prelogin()` → Django authenticate → response `X-Login-Status` → OpenResty ghi failed attempt → Redis atomic count/TTL → lockout/blacklist/reputation → request tiếp theo bị chặn trước Django.

**Các điểm phải phân tích kỹ:**

1. Không tăng failed counter cho GET/PUT/CSRF rejection; chỉ tăng khi Django thật sự trả `failed` cho POST.
2. Exact-match hai route login; nội bộ `X-Login-Status` không chuyển ra client.
3. `ngx.timer.at(0, ...)` đang ghi failed counter bất đồng bộ trên `develop`: kiểm thử race giữa các request; nếu thiếu độ tin cậy thì thiết kế và test phương án ghi đồng bộ ở phase có cosocket hợp lệ, hoặc kiến trúc ack/queue phù hợp. Không tự khẳng định race đã được khắc phục.
4. Lua đang duy trì các key `brute_force:fail:<IP>`, `brute_force:lockout:<IP>`, `blacklist:<IP>`, `risk:v1:<IP>`; kiểm tra cùng DB Redis và cùng canonical client IP.
5. Giải quyết shared IP: lựa chọn rõ IP-only hoặc IP+account với phân tích NAT/CGNAT, account abuse và khả năng tự gây DoS; không thêm khóa tài khoản vĩnh viễn.
6. Redis outage phải có fail-safe, trạng thái emergency lock/test ổn định; không để một lỗi Redis im lặng làm bỏ qua cơ chế bảo vệ.

**Bằng chứng cần lưu:** output `openresty -t`, Docker `ps`, HTTP headers, Redis `GET/TTL` trước/sau, Lua regression summary, log security đã che thông tin nhạy cảm, kết quả concurrent/shared IP.

### III.2. P0.5 — Điểm kỹ thuật cần khóa trước ML

Hiện có sự khác biệt **từ review tĩnh `develop`**: `brute_force_login.lua` dùng TTL reputation cao đến `31,536,000s` ở một nhánh, trong khi `risk_engine.lua` chủ trương TTL bình thường `3,600s`, elevated `7,200s` và auto ban `900s`. Đây là vấn đề nhất quán **chưa khẳng định xảy ra trong local feature**; P0.5 phải xác định module nào có quyền ghi cuối cùng, rồi viết regression test TTL/decay khi hai module cùng tác động.

`RISK_DECAY_ENABLED=true` trên `.env.local` và `false` trên `.env` Production tại thời điểm thảo luận; `RISK_DECAY_FACTOR=0.1`. Code Risk Engine tính decay theo chu kỳ 300 giây **khi có confirmed abuse tiếp theo**, không có timer tự giảm liên tục; không coi cờ bật là bằng chứng mô hình Adaptive đã triển khai. Đừng thay đổi production trước khi kiểm thử chính sách.

### III.3. Điều kiện đóng Baseline Ready

- [ ] P0.1–P0.8 có test report và owner xác nhận, bao gồm toàn bộ P0.2 end-to-end.
- [ ] Không có bypass nghiêm trọng trên authentication/authorization, CSRF, security pipeline.
- [ ] Redis counter/lockout/ban/TTL đạt tiêu chí được công bố, fail-safe và shared IP có báo cáo.
- [ ] Django, Lua, Jenkins và Docker integration tests được ghi log, không chỉ tổng số PASS.
- [ ] Có baseline benchmark, cấu hình versioned, tài liệu rule/reputation/alert và tag Rule-Based.

## IV. GIAI ĐOẠN 2 — P1: AWS VẬN HÀNH & KHẢ NĂNG PHỤC HỒI

**Định hướng:** kế thừa AWS/CI/CD/DockerHub/HTTPS/RDS/S3 hiện có; chỉ kiểm chứng những điểm ảnh hưởng tới demo và tính lặp lại. P1 **không được chặn toàn bộ P2/P3** nếu local lab vẫn đủ điều kiện nghiên cứu.

| Hạng mục | Thực hiện có trọng tâm | Sản phẩm/bằng chứng |
|---|---|---|
| P1.1 AWS & Security Guardrails | Đối chiếu IAM/MFA, budgets, SG, private ports, TLS, secrets, S3 private; không tạo thêm hạ tầng ngoài nhu cầu | Ảnh cấu hình đã che, checklist kiểm tra |
| P1.2 Runtime/Observability | Gateway/Django/Redis/RDS health; Prometheus/Grafana, log rotation, alerting | Dashboard/health reports theo mốc thời gian |
| P1.3 Database Recovery | Chạy restore trên môi trường cô lập, kiểm tra migrations, schema/dữ liệu synthetic và RTO/RPO ghi nhận | Restore evidence + runbook |
| P1.4 Jenkins Rollback | Kiểm thử application rollback và database migration compatibility **riêng biệt** | Log rollback, điều kiện thành công/thất bại |
| P1.5 Redis Persistence & Recovery | Restart, AOF, counters, lockout/blacklist, dữ liệu cần sống qua restart | Recovery report |
| P1.6 EC2 Rebuild / Production Release | Runbook từ image đã versioned, environmental checklist, domain/TLS | Rebuild/redeployment runbook |

**Điều kiện đóng P1:** Có bằng chứng chọn lọc cho các luồng thực sự dùng khi demo; không chấp nhận suy luận “Jenkins SUCCESS” đồng nghĩa DB restore/rollback đã PASS. `feature → develop → main`, DockerHub và Jenkins theo workflow có sẵn.

## V. GIAI ĐOẠN 3 — P2 + P3 + P4: MACHINE LEARNING & ADAPTIVE SECURITY

### V.1. Định nghĩa đóng góp kỹ thuật (điểm mới của bản 2.0)

**Bắt buộc:** (a) mô hình ML thực sự huấn luyện từ feature L7, (b) ảnh hưởng của ML tới quyết định được đo, (c) **Adaptive Decision** điều chỉnh trạng thái hoặc mức giảm thiểu theo hành vi/risk history có kiểm thử. **Không bắt buộc** triển khai adaptive global threshold tự chỉnh mỗi 60 giây hoặc triển khai Z-score như một service production riêng.

**Adaptive ≠ chỉ có Risk Score tĩnh.** Cần chỉ ra trạng thái thay đổi theo chuỗi cửa sổ quan sát hoặc mức tin cậy ML, điều kiện tăng/giảm mức mitigation, giới hạn thời gian và khả năng phục hồi. **Z-score** là thống kê anomaly baseline để so sánh/giải thích; không được gọi là mô hình ML được huấn luyện nếu không có quy trình ML tương ứng.

**Kiến trúc đích (chưa phải trạng thái đã chạy):**

```text
Client / HTTP traffic
    → OpenResty (WAF/JWT/RateLimit/BruteForce/Blacklist)
    → Telemetry + Redis window features (10s/60s)
    → ML inference (async / cached score; internal only)
    → Rule score + ML score + reputation + state history
    → Adaptive Decision Policy (guardrails/hysteresis/TTL)
    → ALLOW / LIMIT / TEMPORARY BLOCK
    ↖ audit/feedback/decay | ML failure → Rule-Based fallback
```

### V.2. P2 — Dataset & Feature Engineering

**Đầu bài ưu tiên:** HTTP Flood lớp 7, phân biệt `normal`/`attack`; thêm `legitimate burst` làm nhóm kiểm chứng đặc biệt. Bot-like behavior và login abuse có thể bổ sung vào lab khi nguồn lực cho phép.

| Nhóm | Công việc | Điều kiện bàn giao |
|---|---|---|
| P2.1 Dataset Protocol | Chọn public dataset hợp lệ + synthetic lab traffic; mô tả nguồn/nhãn/quyền sử dụng | Dataset card và định nghĩa nhãn |
| P2.2 Telemetry | Thu request metadata và kết quả security decision (allow/limit/block) không lộ PII | Schema + log/feature sample |
| P2.3 Window Aggregation | Cửa sổ 10s/60s, per canonical IP hoặc client-session phù hợp; đủ mẫu/TTL | Reproducible aggregation tests |
| P2.4 Feature Schema | `requests_per_10s`, `requests_per_60s`, `avg_interarrival_ms`, `interarrival_std_ms`, `unique_uri_count`, `http_4xx_ratio`, `http_5xx_ratio`, `avg_request_size`, `user_agent_change_count`, `login_failure_count` | Feature spec, types, missing policy |
| P2.5 Split & Version | Chia train/validation/test theo thời gian/client/source độc lập; kiểm tra leakage | Versioned dataset, script tiền xử lý |
| P2.6 Statistical Comparator (optional) | Z-score theo feature (ví dụ RPS/window), baseline 7 ngày chỉ khi có dữ liệu; test `sigma=0`, concept drift | Một báo cáo thống kê đối chứng, **không** yêu cầu module production |

**Giới hạn nghiên cứu:** Không dùng HTTP 4xx/5xx của request đang dự đoán trước khi response tồn tại; nếu dùng chỉ số phản hồi thì lấy từ *window đã hoàn thành*. Với nhiều IP chung NAT cần mô tả bias; dữ liệu bệnh nhân thật, token, cookie và payload nhạy cảm phải loại bỏ. `BASELINE_MIN_SAMPLES=5`, Z=2/3/4 và risk +15/+35/+60 từ cấu hình cũ **chỉ là giả thuyết khởi tạo**, không phải ngưỡng đã được hiệu chuẩn.

**Gate P2 — Dataset Ready:** Có định nghĩa nhãn, schema chung online/offline, split chống leakage, sample tests và quyền sử dụng dữ liệu rõ.

### V.3. P3 — ML Training, Calibration & Independent Evaluation

| Mức | Mô hình/việc | Mục tiêu |
|---|---|---|
| Bắt buộc | **Random Forest** (hoặc một supervised model tương đương nếu dataset đòi hỏi) | ML baseline dễ giải thích, có confusion matrix/feature importance |
| Nên có | **Isolation Forest** | Đối chứng anomaly detection không giám sát; đánh giá được ưu/nhược |
| Tùy thời gian | XGBoost, tối ưu sâu | Chỉ khi không đe dọa milestone tích hợp |
| Bắt buộc | Versioned preprocessing + model + schema + threshold | Train/validation/test tách độc lập, tái tạo được |

**Metrics:** Precision, Recall, F1, FPR = FP/(FP+TN), confusion matrix, PR-AUC khi phù hợp; xem riêng legitimate bursts. Chọn model/threshold trên validation, chỉ mở independent test một lần cho đánh giá chốt. **Block rate khác FPR** và không được dùng thay ground truth.

**Gate P3 — Model Ready:** Có ít nhất 1 model artifact + script training/evaluation + kết quả test độc lập + model version và feature schema.

### V.4. P4 — Hybrid + Adaptive Decision Engine (MVP bắt buộc)

**Phạm vi tối thiểu ưu tiên theo tên đề tài:**

1. **Inference Service nội bộ:** Có thể FastAPI/Flask, `/predict`, `/health`, feature schema validation, model version, timeout và tài nguyên giới hạn; không public trực tiếp.
2. **Lua integration:** OpenResty lưu/tải ML score theo traffic window qua Redis cache hoặc kênh nội bộ, ưu tiên không gọi blocking synchronous inference ở mọi request.
3. **Ba chế độ:** `off` = Rule-Based, `shadow` = ML chỉ quan sát, `enforce` = ML signal tham gia quyết định với guardrails.
4. **Adaptive Decision Policy:** kết hợp rule score + ML confidence + reputation + trạng thái các window trước; ví dụ tăng mitigation theo chuỗi tín hiệu có độ tin cậy cao và hạ mức sau nhiều window bình thường. Dùng hysteresis/cooldown/TTL để tránh dao động liên tục. **Giá trị threshold cần được hiệu chuẩn**, không hardcode tùy tiện.
5. **Quy tắc an toàn:** WAF/JWT/CSRF bắt buộc vẫn độc lập; score ML đơn lẻ không được tạo blacklist dài hạn; Redis/ML timeout phải fallback có test; log decision kèm `model_version`, `policy_version`, lý do và độ trễ, không log PII.
6. **Optional nâng cao:** Adaptive Threshold Engine điều chỉnh global limit/block threshold dựa trên thống kê, **chỉ bổ sung nếu có nhãn/ước lượng FP đáng tin cậy, safe bounds, rollback và thời gian**. Không dùng `block_rate` làm FPR.

**Đặc điểm thích ứng có thể chứng minh:** (a) một IP từ allow sang limit/tạm block sau nhiều window bất thường; (b) sau thời gian và chuỗi window sạch, mức phạt suy giảm theo chính sách; (c) false alarm/legitimate burst ít bị phạt hơn chính sách tĩnh trong phép so sánh có kiểm soát. Các ví dụ là **tiêu chí cần thử**, không phải kết quả có sẵn.

**Gate P4 — Hybrid Ready:** Inference và schema khớp, `off/shadow/enforce` test PASS, score đi vào Gateway, thích ứng có log trạng thái, ML outage fallback, load/latency được đo; bản triển khai demo được xác nhận.

### V.5. Cấu hình môi trường và feature flags

Các nhóm `ADAPTIVE_*` và `BASELINE_*` trong `.env` cũ hiện **chưa có implementation được xác nhận trên `develop`**. Quyết định quản lý cấu hình: chỉ giữ biến thực sự được code sử dụng; xóa nhóm biến chưa dùng khỏi file đang vận hành **sau khi người quản lý xác nhận và tự chỉnh**, bổ sung lại khi có implementation, test và tài liệu. **Không đánh dấu đã xóa** nếu chưa có bằng chứng.

Giữ `RISK_LIMIT_THRESHOLD=50`, `RISK_BLOCK_THRESHOLD=80` như baseline hiện hành trước khi hiệu chuẩn; giữ nguyên decay hiện tại trong P0.2. Các tên biến tương lai như `ML_MODE`, `ADAPTIVE_POLICY_ENABLED`, `MODEL_VERSION` chỉ được thêm lúc tích hợp P4, tránh config giả.

## VI. GIAI ĐOẠN 4 — P5: THỰC NGHIỆM, ĐÁNH GIÁ VÀ BÁO CÁO

### VI.1. Thiết kế nghiên cứu E1–E5 (kế thừa tài liệu gốc)

| Mã | Kịch bản | Mục tiêu |
|---|---|---|
| E1 | Normal HTTP traffic | Đo overhead, false positives trên traffic hợp lệ |
| E2 | Legitimate bursts | Chứng minh không đánh đồng burst với HTTP Flood |
| E3 | HTTP Flood trong lab cô lập | Đánh giá detection/mitigation của Rule vs ML/Adaptive |
| E4 | Bot-like behavior / scripted login abuse | Đánh giá khả năng mở rộng sang hành vi L7 bất thường |
| E5 | Redis/ML timeout, restart, recovery | Kiểm tra độ tin cậy fallback và phục hồi |

### VI.2. Cấu hình đối chứng và phép kiểm tra đóng góp Adaptive

Giữ khung **A–D** từ kế hoạch gốc, **tách cấu hình C thành hai biến thể để kiểm định RQ2**:

| Nhóm | Cấu hình | Mục đích |
|---|---|---|
| A | Django backend trực tiếp trong lab cô lập, không Gateway | Baseline hiệu năng backend |
| B | OpenResty Rule-Based Gateway (ML off) | Baseline bảo mật & hiệu năng |
| C0 | Rule-Based + ML **fusion tĩnh** (không điều chỉnh theo lịch sử/window) | Đo giá trị ML tách biệt với Adaptive |
| C1 | Rule-Based + ML + **Adaptive Decision** | Đo đóng góp riêng của tính thích ứng |
| D | Như C1 nhưng ML service không khả dụng | Fallback/reliability |
| Optional | Z-score statistical comparator trên cùng dataset | So sánh thống kê đơn giản với ML |

Không coi các cấu hình C0/C1 là thay đổi mục tiêu gốc: chúng là *ablation* bên trong mục C. Mọi phép so sánh phải dùng workload/seed/hardware tương đương, nhiều lần chạy và đo biến thiên. Phân biệt metric ở **đơn vị traffic window (ML classification)** với **đơn vị HTTP request (gateway decision)**.

### VI.3. Metric và biểu đồ bắt buộc

| Nhóm | Metric chính |
|---|---|
| Detection | Precision, Recall, F1, FPR, PR-AUC và confusion matrix |
| Performance | RPS, p50/p95/p99 HTTP latency, gateway overhead |
| Resources | CPU/RAM, Redis memory/ops, service resources |
| ML | inference latency, timeout rate, feature freshness, cache hit rate |
| Adaptive | detection delay, mitigation delay, recovery time, số lần policy chuyển trạng thái |
| Reliability | fail-safe/fallback success, HTTP error rate, recovery duration |
| Practicality | chi phí vận hành bổ sung, mức phức tạp tích hợp |

**Điều kiện đóng P5 — Research Validated:** Có raw measurements, script và cấu hình tái lập; đánh giá ML test độc lập, bảng đối chiếu A–D/C0–C1, phân tích kết quả không cải thiện, privacy review, báo cáo các chương 1–5, slide và demo (không sử dụng số liệu minh họa làm kết quả thật).

## VII. LỊCH ƯU TIÊN RÚT GỌN (KHOẢNG 5 TUẦN, CÓ THỂ ĐIỀU CHỈNH)

**Lưu ý:** Đây là lịch đề xuất theo quỹ thời gian còn hơn một tháng, không phải deadline chính thức của trường. Các công việc nghiên cứu nhẹ có thể song song, nhưng **không chuyển P0.3 trước khi P0.2 PASS**.

| Tuần tương đối | Trọng tâm critical path | Có thể song song (không mở rộng hạ tầng) | Mốc đầu ra |
|---|---|---|---|
| **W1** | Hoàn tất P0.2.2–P0.2.4; sau đó P0.3, P0.4 | Định nghĩa dataset/labels và feature schema P2 | Brute-force E2E PASS; CI scope rõ |
| **W2** | P0.5–P0.8, benchmark Rule-Based | Thu synthetic normal/burst/attack lab, chia split | **Baseline Ready** + dataset bản đầu |
| **W3** | P2 finalize + P3 Random Forest train/evaluate | P1 chọn lọc: health/recovery/rollback evidence, không dựng hạ tầng mới | **Dataset Ready + Model Ready** |
| **W4** | P4 inference, shadow, fallback, Adaptive Decision MVP | Chạy so sánh A/B/C0 và chỉnh documentation | **Hybrid Ready** (lab trước prod) |
| **W5** | P5 thí nghiệm A/B/C0/C1/D, số liệu và luận văn | P1 demo-readiness, slide, video/demo script | **Research Validated** |

**Quy tắc giảm phạm vi khi trễ:** Bỏ XGBoost trước → bỏ module Z-score production (giữ comparator offline nếu có) → bỏ global adaptive-threshold auto-tuning → tối ưu mức độ chi tiết AWS rebuild. **Không bỏ** test độc lập ML, fallback, Rule-Based baseline, Adaptive Decision evidence và thực nghiệm C0/C1.

## VIII. QUẢN TRỊ THAY ĐỔI, BẰNG CHỨNG VÀ WORKFLOW

### VIII.1. Quy tắc thực hiện

- Repository GitHub chỉ để **read/review**; người thực hiện đồ án tự sửa code, chạy tests, commit, merge theo `feature → develop → main`.
- Mọi thay đổi code cần chỉ rõ file/vị trí/lý do/đoạn sửa/test; không gắn nhãn PASS nếu chưa thấy log.
- Mỗi mốc nghiệm thu có **commit SHA**, ngày, lệnh chạy, môi trường và bản tóm tắt PASS/FAIL.
- Phân biệt kết quả được báo cáo trong tài liệu cũ với kết quả chạy mới trên feature; không cộng sai test suites khác nhau.
- Production và local `.env` tách biệt; không đưa credentials/secret vào repo, report hoặc log. Benchmark/flood chỉ trong lab được phép.

### VIII.2. Cấu trúc bằng chứng khuyến nghị (chưa tự tạo trong repo)

```text
docs/evidence/
  p0/security-tests/YYYY-MM-DD/
  p0/rule-based-baseline/
  p1/operations-recovery/
  p2/dataset-card-and-schema/
  p3/ml-training-and-evaluation/
  p4/hybrid-shadow-enforce-fallback/
  p5/experiments-A-B-C0-C1-D/
```

Mỗi thư mục nên có README ngắn: mục tiêu, môi trường, lệnh, phiên bản, input, output, PASS/FAIL và liên kết artefact; dữ liệu nhạy cảm được loại bỏ trước khi lưu.

### VIII.3. Bảng theo dõi tức thời và hành động kế tiếp

| Mốc | Trạng thái 18/11 | Bằng chứng đã có | Bước tiếp theo |
|---|---|---|---|
| P0.1 | **PASS** | 8/8 + 84/84; 302 anonymous | Giữ regression, manual Admin/Doctor nếu chưa có |
| P0.2.1 | **PASS** | 91/91 Django tests; 19.981s | Giữ test trong regression |
| P0.2.2 | **OPEN** | Chưa nhận output Gateway/HTTP/Redis sau patch | Chủ dự án gửi `openresty -t`, HTTP headers, Redis counter trước/sau |
| P0.2.3–2.4 | **OPEN** | Lua source/tests tham chiếu `develop` | Kiểm thử threshold, lockout, TTL, concurrency/shared IP/failure |
| P0.3–P0.8 | **OPEN** | Đã có kế hoạch chi tiết | Chỉ thực hiện tuần tự sau khi P0.2 PASS |
| P1 | **PARTIAL/REPORTED** | Compose/Jenkins/README; kết quả triển khai báo cáo | Chọn lọc recovery/rollback/monitoring cần cho demo |
| P2 | **PLANNED** | Feature list và dataset protocol đề xuất | Viết schema + thu dữ liệu mô phỏng không PII |
| P3 | **PLANNED** | Thuật toán và tiêu chí đánh giá đề xuất | Huấn luyện sau khi Dataset Ready |
| P4 | **PLANNED** | Kiến trúc và Adaptive MVP đề xuất | Tích hợp sau Model Ready |
| P5 | **PLANNED** | Kịch bản E1–E5 và cấu hình A–D/C0/C1 | Đo chính thức sau Hybrid Ready |

## IX. NGUỒN TÀI LIỆU VÀ NHẬT KÝ CẬP NHẬT

**Nguồn nội bộ được đối chiếu:** (1) `Ke_hoach_trien_khai_chi_tiet_Do_an_tot_nghiep(1).docx` — kế hoạch 4 giai đoạn lưu ngày 29/10/2026; (2) `Markdown đã dán (1).md` — bản đánh giá điều chỉnh ngày 18/11/2026; (3) `README.revised.md`; (4) `LOCAL_DEVELOPMENT.revised.md`; (5) trao đổi/outputs kiểm thử P0.1, P0.2.1 trong phiên làm việc; (6) review đọc-only một số file `develop` trên GitHub (ngày 18/11/2026). Các thông tin runtime AWS chưa được đo lại trong tài liệu này.

**Nhật ký 18/11/2026 — v2.0:**

1. Cập nhật tiến độ P0.1 (8/8, 84/84) và P0.2.1 (91/91, 19.981 giây); P0.2.2 vẫn OPEN.
2. Không khôi phục lại workstream AWS từ đầu; chuyển sang nghiệm thu vận hành chọn lọc.
3. Bổ sung mục tiêu Adaptive Decision MVP **có trạng thái và có đối chứng C0/C1**; khẳng định rõ Adaptive không mặc định là thay global thresholds theo timer.
4. Đưa Z-score Behavioral Baseline thành comparator thống kê tùy chọn; feature extraction và ML model được huấn luyện vẫn là cốt lõi.
5. Không coi cờ `ADAPTIVE_*`/`BASELINE_*` chưa sử dụng là chức năng đã chạy; tránh đưa cấu hình chưa có implementation vào production.
6. Giữ cấu trúc 4 giai đoạn gốc và 6 workstream thực thi P0–P5, ưu tiên bảo đảm chất lượng nghiên cứu và tiến độ.

**Lần cập nhật tiếp theo:** Sau khi nhận kết quả P0.2.2 từ Gateway, điều chỉnh trạng thái theo log, không sửa các mục PASS đã được chứng minh nếu không xuất hiện hồi quy.
