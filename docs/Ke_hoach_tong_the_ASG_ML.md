# KẾ HOẠCH TRIỂN KHAI TỔNG THỂ ĐỒ ÁN TỐT NGHIỆP

**Đề tài:** Nghiên cứu giải pháp Adaptive Security Gateway phòng chống tấn công lớp 7 dựa trên OpenResty và Machine Learning
**English:** Research on an Adaptive Security Gateway Solution for Defending Against Layer 7 Attacks Based on OpenResty and Machine Learning
**Phiên bản kế hoạch:** 2.2 — cập nhật ngày 22/11/2026 (đối chiếu nghiệm thu P0.3 và hồ sơ P0.2)
**Repository tham chiếu:** https://github.com/NTNguyen055/Adaptive-Security-Gateway
**Nhánh đang phát triển:** `feature/p0-security-baseline`; **checkpoint P0.2:** `4e7b350` (21/11/2026); **checkpoint source/test P0.3:** `b510488` (22/11/2026); **remote HEAD đã đối chiếu:** `7c51a35` (22/11/2026, báo cáo P0.3 hoàn thiện). Đây là các **feature checkpoints**, chưa phải merge `develop`/`main`.
**Nguyên tắc:** Chủ dự án tự sửa mã nguồn, kiểm thử, commit và merge; trợ lý chỉ đọc/review mã nguồn GitHub và đưa đề xuất.

> **Quy tắc trạng thái:** `PASS` = đã có output kiểm thử phù hợp phạm vi được nêu; `TECHNICAL PASS (LOCAL/SHADOW)` = nghiệm thu kỹ thuật trong local, không suy rộng sang production; `FORMAL PENDING` = còn việc đóng hồ sơ/bằng chứng; `CODE` = có source nhưng chưa có đủ chứng cứ vận hành; `REPORTED` = kết quả lịch sử chưa kiểm chứng lại; `OPEN` = chưa nghiệm thu; `PLANNED` = chưa triển khai. Không coi commit, cấu hình hoặc điểm Risk là bằng chứng phát hành ban IP tự động thành công.

## I. TÓM TẮT ĐIỀU HÀNH VÀ MỤC TIÊU NGHIÊN CỨU

Kế hoạch **giữ 4 giai đoạn lớn của tài liệu gốc (29/10/2026)**: (1) hoàn thiện nền tảng bảo mật, (2) triển khai/vận hành AWS, (3) nghiên cứu và tích hợp Machine Learning, (4) thực nghiệm và hoàn thiện luận văn. Để dễ quản lý khối lượng còn lại, các việc được triển khai qua **6 workstream P0–P5**; đây là cách chia tiến độ, **không thay thế** cấu trúc 4 giai đoạn gốc.

**Mục tiêu cuối cùng:** xây dựng và đánh giá một Gateway lớp 7 có khả năng (i) phòng vệ rule-based ổn định trên OpenResty, (ii) phát hiện hành vi bất thường bằng ML đã huấn luyện, (iii) đưa ra phản ứng thích ứng có trạng thái và giới hạn an toàn, (iv) chứng minh hiệu quả, chi phí và khả năng chịu lỗi bằng thực nghiệm có thể tái lập.

**Ba câu hỏi nghiên cứu:**

- **RQ1 — Hiệu quả phát hiện:** Kết hợp Machine Learning có cải thiện Recall/F1 với HTTP Flood và hành vi bot-like so với Rule-Based Gateway hay không, và đánh đổi FPR là bao nhiêu?
- **RQ2 — Giá trị Adaptive:** Với cùng mô hình ML, chính sách phản ứng thích ứng theo hành vi/risk history có cải thiện thời gian giảm thiểu tấn công, khả năng phục hồi và false positive đối với legitimate burst so với quyết định tĩnh hay không?
- **RQ3 — Tính khả thi thực tế:** Chi phí p95/p99 latency, throughput, CPU/RAM/Redis và hành vi fallback khi Redis/ML lỗi có chấp nhận được không?

**Nguyên tắc thiết kế:** Rule-Based luôn là lớp bảo vệ độc lập; ML không được trở thành single point of failure; không sử dụng dữ liệu bệnh nhân thật hoặc token/cookie/password trong dataset/log; không thử flooding gây gián đoạn trên production.

### I.1. Bản đồ 4 giai đoạn và 6 workstream

| Giai đoạn gốc | Workstream | Trọng tâm | Trạng thái cập nhật 22/11/2026 |
|---|---|---|---|
| GĐ1 — Rule-Based Security Baseline | **P0** | Authorization, NAT-aware login security, authorized ban/correlator shadow, CSRF, CI, Risk/TTL, WAF/privacy, benchmark | **P0.1 PASS; P0.2 TECHNICAL PASS (LOCAL/SHADOW), FORMAL PENDING; P0.3 LOCAL TECHNICAL ACCEPTANCE PASS; P0.4–P0.8 OPEN; chưa Baseline Ready** |
| GĐ2 — AWS Deployment & Operations | **P1** | Rà soát tình trạng triển khai, recovery, rollback, monitoring, chi phí | **Nền tảng có mã và có báo cáo vận hành; cần nghiệm thu chọn lọc** |
| GĐ3 — ML Research & Hybrid | **P2 + P3 + P4** | Dataset/feature → training → inference + Adaptive Decision | **PLANNED; chưa có bằng chứng triển khai hoàn chỉnh** |
| GĐ4 — Experiments & Thesis | **P5** | E1–E5; A–D + ablation; báo cáo/slide/demo | **PLANNED; có thiết kế kịch bản, chưa có kết quả cuối** |

### I.2. Mốc bắt buộc

1. **Baseline Ready:** P0.1–P0.8 đạt điều kiện nghiệm thu, có test report, cấu hình được phiên bản hóa và benchmark Rule-Based.
2. **ML Model Ready:** Dataset và schema tái lập; một mô hình được huấn luyện, đánh giá trên test độc lập và đóng gói có version.
3. **Hybrid Ready:** OpenResty nhận ML signal; chế độ `off/shadow/enforce`; Adaptive Decision và fallback có test.
4. **Research Validated:** Có số liệu A–D và đối chứng *ML có/không có Adaptive*; đồ thị, phân tích giới hạn, luận văn và demo.

## II. ĐÁNH GIÁ TIẾN ĐỘ THỰC TẾ (CẬP NHẬT ĐẾN NGÀY 22/11/2026)

### II.1. Thành phần đã có và bằng chứng

| Nhóm | Nội dung đã thực hiện hoặc có cơ sở | Trạng thái và nguồn bằng chứng |
|---|---|---|
| Local development | Compose local, MySQL, Redis, Django, OpenResty; gateway chỉ publish `127.0.0.1:80/443` | **PASS local:** Redis/App/Gateway đều Healthy sau rollback (21/11); `LOGIN_ACCOUNTING_ENABLED=False`, Correlator Shadow `false` |
| Authorization P0.1 | `PROFILE`/`CHANGE_PASSWORD`, form/session, `PROFILE_UPDATE` POST-only | **PASS lịch sử:** 8/8 authorization và 84/84 Django regression (18/11); một số manual role flows còn ghi nhận riêng |
| P0.2.1 — Django login contract | POST-only, nội bộ `X-Login-Status`, xác thực thành công/thất bại | **PASS:** 91/91 Django regression (18/11); valid-account HTTP E2E bổ sung 9/9 (21/11) |
| P0.2.2 — Gateway login integration | Exact login locations, chặn header nội bộ, canonical/trusted peer IP, kiểm tra CSRF/session qua Gateway | **TECHNICAL PASS local** theo `openresty -t`, valid-account E2E 9/9 và các HTTP tests; còn cần lưu đủ bản HTTP method/status matrix nguyên văn để đóng hồ sơ gốc |
| P0.2.3 — NAT-aware accounting | Bỏ legacy IP-only failed-login lockout; Redis V3 account+pair counters, bounded backoff, admit/finalize atomic, HMAC pseudonyms | **TECHNICAL PASS local:** V3 isolated E2E 11/11; Redis atomic/CAS tests theo kết quả đã báo cáo; không phát hành IP ban từ thất bại đăng nhập |
| P0.2.4 / A3.1–A3.4 | Ban authorization, Redis V2 TTL+metadata, legacy audit, Security Correlator Shadow và E2E | **TECHNICAL PASS local/shadow:** Gateway LuaJIT 145/145 (13 suites), authorized-ban HTTP 10/10, blacklist HTTP 13/13, Redis CAS 16/16, shadow 8 events/3 windows/2 classes; tự động ban từ correlator vẫn fail-closed |
| Git checkpoint P0.2 | `feature/p0-security-baseline`; A3.3 `263ea9e`; A3.4 `4e7b350` (14 file) | **HISTORICAL CHECKPOINT:** P0.2 source tại `4e7b350` (21/11); các cập nhật tài liệu P0.2 đang được rà soát/chuẩn bị commit riêng sau P0.3, không gộp kết quả thử nghiệm giữa các SHA |
| P0.3 — CSRF & Authentication Request Security | Origin/Referer/CSRF, logout POST-only, session, HTTP methods, RBAC Admin/Doctor, proxy trust boundary | **LOCAL TECHNICAL ACCEPTANCE PASS (22/11):** HTTP Method Inventory 16/16; Role Matrix 14/14; CSRF/Auth 20/20 (đều nằm trong Django regression 114 discovered / 102 PASS / 12 skipped); HTTPS E2E 37/37, Proxy Trust 19/19, Admin/Doctor E2E 36/36; checkpoint source/test `b510488`; tài liệu đã push tại `7c51a35` |
| Lua historical tests | 97/97 Lua; 17/17 Django isolated (17/11) | **REPORTED lịch sử**, không cộng vào 145 tests mới |
| Jenkins / DockerHub | CI và image workflow có trong repository | **CODE + REPORTED:** chưa có CI artifact cho tất cả thay đổi P0.2 tại SHA này; P0.4 vẫn OPEN |
| AWS / RDS / S3 / TLS | Cấu hình hạ tầng và tài liệu vận hành trước đây | **CODE + REPORTED:** chưa nghiệm thu lại production/AWS trong phiên P0.2; P1 không được mặc định PASS |
| ML / Adaptive | Dataset, ML inference, policy thích ứng và thí nghiệm A–D/C0/C1 | **PLANNED**, không có bằng chứng đã huấn luyện/tích hợp model từ P0.2 |

**Nguồn nghiệm thu:** P0.2 tại `docs/P0_2_SECURITY_ACCEPTANCE_2026-11-21.md` (file local sẽ commit riêng), source/checkpoint `4e7b350`, log local 18–21/11; P0.3 tại `docs/P0_3_SECURITY_ACCEPTANCE_2026-11-22.md` và `docs/HTTP_METHOD_INVENTORY_P03.md`, source/test `b510488`, tài liệu tại `7c51a35`, log local ngày 22/11. Các báo cáo này không phải artifact do GitHub Actions/Jenkins tự sinh.

**Lưu ý lịch sử:** Các tuyên bố về `develop`, AWS và IP-only lockout ở bản kế hoạch v2.0 phản ánh lần review 18/11; không được áp dụng nguyên trạng cho feature branch `4e7b350`. Bản v2.1 lấy kiến trúc NAT-aware/issuer/correlator thực tế làm cơ sở kỹ thuật mới.

### II.2. Các phạm vi chưa được phép tuyên bố PASS / việc đóng hồ sơ

- **P0.2 có TECHNICAL PASS trong local/shadow, nhưng formal closure còn cần:** commit/push tài liệu kế hoạch/Correlator và báo cáo nghiệm thu sau review; đối chiếu log HTTP method/status matrix P0.2 (đặc biệt `405/403/302`) và Redis recovery/AOF nếu là gate bắt buộc của checklist gốc. Các HTTP Method tests P0.3 không tự động thay thế log lịch sử P0.2. Không điền PASS cho thử nghiệm chưa có log tương ứng.
- **Automatic ban từ Correlator chưa được phép bật:** `security_correlator.verify()` chủ động trả lỗi do thiếu independent confirmed-exploit verifier và NAT/CGNAT low-collateral assessment. E2E ban 10/10 dùng Redis EVAL với incident **synthetic**, chỉ chứng minh persistence/enforcement/expiry, **không** chứng minh trusted correlator issuance production.
- **Shadow Policy mismatch 403/503** đã quan sát khi WAF chặn trước JWT; đây là độ lệch so sánh do short-circuit cần regression/phân loại, không phải khẳng định live Gateway đã trả 503.
- **P0.3 đã đạt LOCAL TECHNICAL ACCEPTANCE PASS** tại source/test checkpoint `b510488`, với tài liệu nghiệm thu được push đến `7c51a35` (22/11/2026). **P0.4–P0.8 vẫn OPEN** (CI, Risk/TTL tổng thể, WAF privacy, benchmark và Baseline Ready). Không suy ra hiệu năng, FPR hay production readiness từ các unit/E2E PASS.
- **Credentials local đã chia sẻ** trước đây cần rotation theo quy trình có kiểm soát; không lưu bí mật vào source, báo cáo hoặc Git. Chưa có bằng chứng việc rotation đã hoàn thành.

## III. GIAI ĐOẠN 1 — P0: HOÀN TẤT SECURITY BASELINE

**Mục tiêu:** chốt phiên bản Rule-Based Gateway chính xác, có thể lặp lại, không gây hồi quy Django và có dữ liệu đo baseline phục vụ so sánh ML. **P0.2 đạt nghiệm thu kỹ thuật trong local/shadow ở checkpoint `4e7b350`**, còn formal closure; **P0.3 đạt LOCAL TECHNICAL ACCEPTANCE PASS tại source/test checkpoint `b510488`**. Không mở rộng quyền automatic ban khi chuyển sang P0.4–P0.8.

| Mã | Nội dung thực tế / file trọng điểm | Trạng thái cập nhật 22/11/2026 | Giới hạn và điều kiện đóng |
|---|---|---|---|
| **P0.1** | Authorization: Django views/templates, tests | **PASS lịch sử** | 8/8 P0.1; 84/84 regression; manual Admin/Doctor nếu cần ghi riêng |
| **P0.2.1** | Django login status, `@require_POST`, session/auth | **PASS** | 91/91 Django tests (18/11); valid-account E2E bổ sung |
| **P0.2.2** | Gateway login HTTP contract, internal-header stripping, trusted client IP | **TECHNICAL PASS local; hồ sơ method matrix cần đối chiếu** | `openresty -t`; V3 login 9/9; log `405/403/302` cần lưu nếu là gate nguyên văn |
| **P0.2.3** | NAT-aware account/pair accounting tại `docappsystem/docappsystem/login_accounting.py`; `brute_force_login.lua` giữ telemetry/fallback | **TECHNICAL PASS local** | Redis atomic admit/finalize, bounded backoff, no legacy IP-only punishment; không giữ lại yêu cầu khóa toàn bộ IP tại ngưỡng 5 thất bại |
| **P0.2.4 / A3.1–A3.4** | IP ban authorization, issuer, blacklist read/enforcement, correlator shadow, legacy audit, live integration | **TECHNICAL PASS local/shadow** | 145/145 LuaJIT; ban 10/10, blacklist 13/13, CAS 16/16, valid login 9/9, correlator shadow 8/3/2; recovery/AOF archive nếu là gate |
| **P0.2 — tổng thể** | NAT-aware login security + authorized ban storage + WAF shadow correlation | **TECHNICAL PASS (LOCAL/SHADOW) / FORMAL PENDING** | Đồng bộ tài liệu, đối chiếu checklist còn thiếu, không suy rộng production |
| **P0.3** | CSRF/Origin/Referer, session/logout POST-only, HTTP Method Inventory, Admin/Doctor RBAC và Proxy Trust | **LOCAL TECHNICAL ACCEPTANCE PASS** | Django 114 discovered / 102 PASS / 12 skipped; HTTP Method Inventory 16/16; Authenticated HTTPS 37/37, Proxy Trust 19/19, Admin/Doctor HTTPS 36/36; `docs/P0_3_SECURITY_ACCEPTANCE_2026-11-22.md`; source/test `b510488`, docs `7c51a35` |
| **P0.4** | Django/Lua/Gateway tests trong Jenkins CI, artifact reports | **OPEN** | CI trên commit mới chạy suite cần thiết và lưu artifact |
| **P0.5** | Risk weights, Redis reputation/decay, TTL, ban/unban policy | **OPEN** | Tổng kiểm toán policy/TTL và độ nhất quán cho baseline, không tái sử dụng IP lockout gây hại NAT |
| **P0.6** | WAF SQLi/XSS false positives, log privacy | **OPEN** | Rà soát raw query/payload trong error logs và retention |
| **P0.7** | Rule-Based benchmark trong local lab | **OPEN** | p50/p95/p99, RPS, CPU/RAM, legitimate burst và FP/FN có nhãn |
| **P0.8** | Baseline version/tag, test matrix, báo cáo và config snapshot | **OPEN** | Gate Baseline Ready yêu cầu P0.1–P0.8, không chỉ P0.2 |

### III.1. P0.2 — Kiến trúc đã triển khai và bằng chứng

**Luồng đăng nhập với V3 ON trong local E2E:** `POST /doLogin/` → OpenResty xác thực nguồn IP và kiểm tra prelogin → Django `LoginAccounting.admit()` atomic → Django authenticate → `LoginAccounting.finalize()` atomic → **chỉ khi finalize success được xác nhận mới tạo Django session** → các header `X-Login-*` nội bộ không được đưa cho client. Khi Redis trả lỗi/không xác nhận trạng thái, luồng liên quan fail-closed thay vì âm thầm tạo session.

**Nguyên tắc NAT-aware:** failed-login accounting theo account+source (HMAC pseudonyms trong `bf:v3:*`, Redis DB0), kèm bounded backoff và telemetry spraying; **không** biến đếm sai mật khẩu thành `blacklist:<IP>`, IP lockout hoặc reputation penalty chỉ vì cùng IP. Một backoff tài khoản vẫn có thể tạm trì hoãn người dùng hợp lệ khi tài khoản bị tấn công; đây là rủi ro chấp nhận có giới hạn, không phải bảo đảm zero-DoS.

**Phân quyền ban IP:** `ip_ban_authorizer.lua` là contract xét điều kiện → `ip_ban_issuer.lua` kiểm tra lại và ghi `ban:v2:ip:<ip>` bằng Redis atomic `SET NX EX`, TTL tối đa 300s và metadata cùng key → `ip_blacklist.lua` đọc/thực thi. Manual ban trong `blacklist_ips` và Legacy TTL key `blacklist:<ip>` là hai quyền khác nhau; script audit Legacy **chỉ đọc**, không tự xóa/chuyển đổi trạng thái không rõ provenance.

**Security Correlator:** `security_signal_adapter` gắn nguồn WAF theo step, `security_shadow.log()` chuyển request-verified traces sang `security_correlator.lua`, theo dõi tối thiểu **8 requests / 3 cửa sổ 60s / 2 lớp WAF** trong 5 buckets gần nhất. Kết quả **`SUSPICIOUS_SHADOW`** không chứng minh exploit đã thành công, hai detector độc lập hay IP an toàn để ban. `verify()` vẫn fail-closed cho mọi incident; không có automatic issuance production từ correlator.

| Bằng chứng kiểm thử | Kết quả đã báo cáo | Phạm vi diễn giải |
|---|---|---|
| Gateway LuaJIT offline regression | **145/145 PASS**, 13 suites | Bao gồm correlator 23/23 và issuer 12/12; không phải toàn bộ Django/Jenkins |
| Redis + HTTP authorized-ban lifecycle | **10/10 PASS** | Synthetic Redis EVAL, TTL/metadata/HTTP 403/expiry; không phải correlator production issue |
| HTTP Legacy/manual blacklist | **13/13 PASS** | Manual ban/unban, Legacy TTL auto, khôi phục HTTP 200 |
| Reputation Redis CAS concurrency | **16/16 PASS** | Reject stale update, retry đúng snapshot, không ghi đè state |
| Valid-account V3 HTTP E2E | **9/9 PASS** | Django session, success marker, spoofed `X-Real-IP` bị Gateway thay thế, rollback flag OFF |
| V3 NAT-aware login HTTP E2E | **11/11 PASS** (giai đoạn A3.3) | Account/pair counters, shared-IP không bị ban; số liệu thuộc lần chạy khác |
| Correlator Shadow HTTP | **PASS: 8 events, 3 windows, 2 classes** | Docker logs `[SECURITY_CORRELATOR] ... automatic_ban=disabled` |
| Final local rollback | **PASS** | Gateway/App/Redis Healthy; `LOGIN_ACCOUNTING_ENABLED=False`, `SECURITY_CORRELATOR_SHADOW_ENABLED=false` |

**Lưu ý các khoảng trống cần bảo quản:** Kết quả `openresty -t` và E2E được chủ dự án cung cấp; báo cáo nghiệm thu chưa phải Jenkins CI artifact. Bộ HTTP `405/403/302` đầy đủ và bản Redis AOF/recovery nguyên gốc chưa được đối chiếu trong checkpoint này; không dùng bảng trên thay thế chúng. Log WAF/OpenResty có thể chứa query/payload và thông tin định danh trong `docker logs`, cần redaction trước khi lưu lâu dài.

**Nguồn tham chiếu P0.2 cố định:** SHA `4e7b350` (21/11/2026), `docs/SECURITY_CORRELATOR.md`, `docs/P0_2_SECURITY_ACCEPTANCE_2026-11-21.md`. **Nguồn P0.3:** source/test `b510488`, tài liệu `7c51a35`, `docs/P0_3_SECURITY_ACCEPTANCE_2026-11-22.md`. Không gắn nhãn ML production, full automatic IP ban hoặc global Rule-Based Baseline Ready.

### III.2. P0.5 — Điểm kỹ thuật cần khóa trước ML

**Mốc nguồn hiện tại cần kiểm toán:** `4e7b350` có các module Redis Rate Limiter, Risk Engine, Reputation CAS/decay, blacklist Manual/Legacy/V2. Ở A3.1–A3.4, Risk Engine và legacy failed-login accounting **không còn thẩm quyền tự cấp IP ban**. Kết quả tests riêng đã chứng minh các nhánh rate-only/context-only và một số lỗi Redis không tự nâng thành IP punishment; P0.5 vẫn phải kiểm toán tổng thể toàn bộ TTL, thứ tự áp dụng policy, side effects và false positives.

Cảnh báo về TTL reputation dài `31,536,000s` và auto-ban `900s` trong bản kế hoạch 18/11 xuất phát từ **review lịch sử của nhánh `develop`**, không được coi là cấu hình đang hoạt động ở commit feature hiện tại. P0.5 phải đối chiếu từ source thực tế và bài test, không khôi phục hành vi khóa IP gây collateral damage trên NAT.

`RISK_DECAY_ENABLED` và `RISK_DECAY_FACTOR` chỉ điều khiển logic decay của Risk Engine; không chứng minh có Adaptive Decision/ML. Chưa có số liệu benchmark hoặc FPR thực nghiệm chính thức tại thời điểm cập nhật tài liệu.

### III.3. Điều kiện đóng Baseline Ready

- [ ] P0.1–P0.8 có test report và owner xác nhận, bao gồm toàn bộ P0.2 end-to-end.
- [ ] Không có bypass nghiêm trọng trên authentication/authorization, CSRF, security pipeline.
- [ ] Redis account/pair accounting, ban TTL, rollback và shared NAT có test matrix/báo cáo; không yêu cầu IP-only lockout kiểu cũ.
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

**Lưu ý:** Đây là lịch đề xuất tương đối, không phải deadline chính thức của trường. Tại mốc 22/11, P0.3 đã có **LOCAL TECHNICAL ACCEPTANCE PASS**, P0.2 còn formal closure; ưu tiên P0.2 evidence reconciliation, P0.4 CI và P0.5–P0.8. Không coi toàn bộ P0 đã hoàn tất.

| Tuần tương đối | Trọng tâm critical path | Có thể song song (không mở rộng hạ tầng) | Mốc đầu ra |
|---|---|---|---|
| **W1** | Chốt hồ sơ/evidence còn thiếu của P0.2; hoàn thiện checkpoint P0.3 đã PASS; mở P0.4 CI | Định nghĩa dataset/labels và feature schema P2 | Hồ sơ P0.2 đối chiếu gate, P0.3 local acceptance và CI scope rõ |
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

| Mốc | Trạng thái cập nhật 22/11 | Bằng chứng đã có | Bước tiếp theo |
|---|---|---|---|
| P0.1 | **PASS lịch sử** | 8/8 + 84/84; anonymous 302 | Giữ regression, bổ sung manual roles nếu cần |
| P0.2.1 | **PASS** | 91/91 Django tests (18/11); valid-account 9/9 (21/11) | Gắn báo cáo và log theo mốc |
| P0.2.2 | **TECHNICAL PASS local; FORMAL PENDING** | `openresty -t`, V3 E2E/header/trusted IP | Đối chiếu/lưu HTTP method/status matrix 405/403/302 |
| P0.2.3 | **TECHNICAL PASS local** | NAT-aware V3, Redis atomic, shared-IP tests | Không khôi phục IP-only lockout; tài liệu hóa rollout flag |
| P0.2.4 / A3.1–A3.4 | **TECHNICAL PASS local/shadow** | LuaJIT 145/145; ban 10/10; blacklist 13/13; CAS 16/16; valid login 9/9; shadow 8/3/2 | Kiểm tra AOF/recovery evidence nếu là gate; đồng bộ docs |
| P0.2 tổng thể | **TECHNICAL PASS (LOCAL/SHADOW) / FORMAL PENDING** | Commit `4e7b350`, báo cáo ASG/P0.2/ACC-01 | Chốt hồ sơ P0.2; không bật automatic issuance |
| P0.3 | **LOCAL TECHNICAL ACCEPTANCE PASS** | Django regression 114 tests (102 PASS, 12 skipped); HTTP Method Inventory 16/16; HTTPS E2E 37/37, Proxy 19/19, Admin/Doctor 36/36; SHA `b510488` và docs `7c51a35` | Giữ regression; không suy rộng production |
| P0.4–P0.8 | **OPEN** | Kế hoạch CI, Risk/TTL, WAF/privacy, benchmark, baseline tag | Thực hiện từng gate và lưu evidence |
| P1 | **PARTIAL / REPORTED** | Compose/Jenkins/AWS code và lịch sử vận hành | Recovery/rollback/monitoring demo readiness |
| P2 | **PLANNED** | Dataset protocol/feature proposal | Tạo dataset card và schema không PII |
| P3 | **PLANNED** | Model/evaluation plan | Train sau khi Dataset Ready |
| P4 | **PLANNED** | Hybrid/Adaptive MVP plan | Enforce chỉ sau model, safety, fallback tests |
| P5 | **PLANNED** | E1–E5 và cấu hình A–D/C0/C1 | Thu số liệu thực nghiệm có thể tái lập |

**Chốt thay đổi:** P0.2 giữ phạm vi kỹ thuật local/shadow theo log và source checkpoint; P0.3 được nghiệm thu local theo các bộ test độc lập đã cung cấp. Không suy rộng sang production/AWS, CI trên GitHub, ML hoặc merge code.

## IX. NGUỒN TÀI LIỆU VÀ NHẬT KÝ CẬP NHẬT

**Nguồn nội bộ được đối chiếu:** (1) `Ke_hoach_trien_khai_chi_tiet_Do_an_tot_nghiep(1).docx` — kế hoạch 4 giai đoạn lưu ngày 29/10/2026; (2) `Markdown đã dán (1).md` — bản đánh giá điều chỉnh ngày 18/11/2026; (3) `README.revised.md`; (4) `LOCAL_DEVELOPMENT.revised.md`; (5) trao đổi/outputs kiểm thử P0.1, P0.2.1 trong phiên làm việc; (6) review đọc-only một số file `develop` trên GitHub (ngày 18/11/2026). Các thông tin runtime AWS chưa được đo lại trong tài liệu này.

**Nhật ký 18/11/2026 — v2.0:**

1. Cập nhật tiến độ P0.1 (8/8, 84/84) và P0.2.1 (91/91, 19.981 giây); P0.2.2 vẫn OPEN.
2. Không khôi phục lại workstream AWS từ đầu; chuyển sang nghiệm thu vận hành chọn lọc.
3. Bổ sung mục tiêu Adaptive Decision MVP **có trạng thái và có đối chứng C0/C1**; khẳng định rõ Adaptive không mặc định là thay global thresholds theo timer.
4. Đưa Z-score Behavioral Baseline thành comparator thống kê tùy chọn; feature extraction và ML model được huấn luyện vẫn là cốt lõi.
5. Không coi cờ `ADAPTIVE_*`/`BASELINE_*` chưa sử dụng là chức năng đã chạy; tránh đưa cấu hình chưa có implementation vào production.
6. Giữ cấu trúc 4 giai đoạn gốc và 6 workstream thực thi P0–P5, ưu tiên bảo đảm chất lượng nghiên cứu và tiến độ.

**Nhật ký 21/11/2026 — v2.1 (P0.2 technical acceptance):**

1. GitHub remote branch `feature/p0-security-baseline` xác nhận commit A3.4 `4e7b350`, parent `263ea9e` (A3.3); 14 file thay đổi, không suy ra đã merge `develop`/`main`.
2. Cập nhật A3.1–A3.4: Risk Engine không tự ban; issuer chỉ ghi ban đã được policy cho phép, Redis TTL <=300s, phân biệt manual/legacy/V2; correlator Shadow là *evidence aggregation*, `verify()` fail-closed.
3. Ghi nhận 145/145 Gateway LuaJIT, authorized ban 10/10, blacklist 13/13, Redis CAS 16/16, valid-account V3 9/9 và Correlator Shadow 8 events/3 windows/2 classes; Redis/Django/Gateway healthy và flags được rollback về OFF.
4. Sửa phần mô tả IP-only lockout không còn tương thích NAT-aware V3; ghi rõ ranh giới local/shadow, synthetic EVAL test, các cảnh báo về shared NAT và dữ liệu log.
5. Đánh dấu `P0.2 = TECHNICAL PASS (LOCAL/SHADOW) / FORMAL PENDING` tại mốc lịch sử 21/11; khi đó P0.3–P0.8 vẫn OPEN (trạng thái P0.3 đã được cập nhật trong nhật ký ngày 22/11 bên dưới).
6. Phát hành tham chiếu báo cáo ASG/P0.2/ACC-01 (`P0_2_SECURITY_ACCEPTANCE_2026-11-21.md`), giữ phân biệt evidence thực tế với đề xuất nghiên cứu P2–P5.

**Nhật ký 22/11/2026 — v2.2 (P0.3 local technical acceptance):**

1. P0.3 đã hoàn thiện CSRF, Origin/Referer, logout POST-only, HTTP methods, session, role separation và proxy trust trong local lab.
2. HTTP Method Inventory trải qua RED baseline (**100 assertion failures, 12 errors** ở 11 test methods) rồi GREEN (**16/16 test methods PASS**) sau method hardening; các subtests không được tính là lỗ hổng độc lập.
3. Django full offline regression: **114 discovered / 102 executed PASS / 12 intentional skips**. Các nhóm 20 CSRF/Auth, 14 Role Matrix và 16 Inventory **đã nằm trong** 114, không cộng lặp.
4. HTTPS E2E: authenticated flow **37/37**, proxy trust **19/19**, Admin/Doctor sessions **36/36**; chỉ xác nhận local lab, không phải production hoặc browser automation.
5. Source/test checkpoint: `b510488`; P0.3 documentation được hoàn thiện/push tại `7c51a35` trên `feature/p0-security-baseline`. Báo cáo: `docs/P0_3_SECURITY_ACCEPTANCE_2026-11-22.md`; inventory: `docs/HTTP_METHOD_INVENTORY_P03.md`.
6. Kết luận: **P0.3 LOCAL TECHNICAL ACCEPTANCE PASS**; **P0.2 FORMAL PENDING** tới khi đối chiếu evidence HTTP method matrix lịch sử và Redis recovery/AOF theo checklist gốc; **P0.4–P0.8 OPEN**, Rule-Based Baseline Ready chưa đạt.

**Lần cập nhật tiếp theo:** Commit/push ba tài liệu P0.2 cùng script test maintenance sau review; ghi SHA mới mà không thay checkpoint P0.2 `4e7b350` hoặc P0.3 `b510488`; hoàn tất các gate lịch sử của P0.2 trước formal closure; tiếp tục P0.4–P0.8.
