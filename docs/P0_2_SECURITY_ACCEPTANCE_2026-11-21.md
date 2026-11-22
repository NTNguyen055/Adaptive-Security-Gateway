# BÁO CÁO NGHIỆM THU KỸ THUẬT P0.2

**Adaptive Security Gateway + Machine Learning for Layer 7**  
**Chuyên ngành:** An toàn thông tin – Đồ án tốt nghiệp  
**Mã báo cáo:** ASG/P0.2/ACC-01 | **Phiên bản:** 1.0  
**Ngày lập:** 21/11/2026 | **Môi trường:** Local Docker Compose / OpenResty / Django / Redis / MySQL  
**Kết luận:** **TECHNICAL ACCEPTANCE: PASS (LOCAL / SHADOW)**; **FORMAL DOCUMENTATION CLOSURE: PENDING**

> **Ranh giới tuyên bố:** Báo cáo xác nhận các chức năng đã được triển khai và kiểm thử trong local lab; không xác nhận khả năng vận hành production, kết quả benchmark hiệu năng, hay quyền tự động cấp IP ban từ correlator thực tế. Số liệu chạy thử đến từ log do người thực hiện cung cấp; đối chiếu source/commit trên GitHub ngày 21/11/2026. Không đính kèm secret, IP cá nhân, request thực hoặc dữ liệu tài khoản.

## 1. Thông tin checkpoint và xuất xứ bằng chứng

| Trường | Giá trị |
|---|---|
| Repository | `NTNguyen055/Adaptive-Security-Gateway` |
| Nhánh | `feature/p0-security-baseline` |
| Remote HEAD tại thời điểm nghiệm thu P0.2 | `4e7b350c6e7adc0a9ee2920be29eaf70622ffd21` |
| Commit message | `feat(security): add authorized ban persistence and shadow correlator` |
| Commit cha | `263ea9eb834c8027a75a8d30555acbcffbcecda5` (A3.3) |
| Thay đổi trong A3.4 | 14 file: 8 file mới, 6 file chỉnh sửa; 1.974 dòng thêm, 173 dòng xóa (theo Git commit) |
| Ngày Git commit | 21/11/2026 (GitHub ghi `2026-11-21T16:10:19Z`) |
| Trạng thái Git local sau push | **Có 1 file còn chỉnh sửa chưa commit:** `docs/SECURITY_CORRELATOR.md` |
| Phạm vi ghi nhận | Kiểm thử local; feature branch; cơ chế automatic issuance vẫn fail-closed |

**Xác minh lịch sử:** Tại ngày 21/11/2026, GitHub API xác nhận nhánh `refs/heads/feature/p0-security-baseline` trỏ tới `4e7b350`. Commit gồm `ip_ban_issuer.lua`, `security_correlator.lua`, cập nhật `ip_blacklist.lua`, `security_shadow.lua`, `nginx.conf`, tài liệu và các bài test. Khi đó còn tài liệu local chưa commit. **Cập nhật 22/11/2026:** remote branch đã tiến tới `7c51a35` sau khi nghiệm thu P0.3. **Mốc kiểm thử P0.2 vẫn là `4e7b350`**; việc tiến branch không chứng minh P0.2 đã được kiểm thử lại trên source mới.

## 2. Mục tiêu P0.2 và phạm vi nghiệm thu

P0.2 giải quyết an toàn luồng đăng nhập Layer 7 qua Gateway, phân biệt tín hiệu request/risk với quyền phạt IP, đồng thời bảo đảm tương thích NAT/CGNAT, trạng thái Redis nhất quán và có cơ chế quan sát hành vi nhiều request.

**Các tiêu chí chính:**

1. `POST /doLogin/` được kiểm soát bằng Django CSRF và xác thực; tín hiệu kế toán nội bộ không lộ ra client.
2. Account-Aware Login Accounting V3 được bảo vệ bằng feature flag, có Redis Lua atomic `admit/finalize`, không tự tạo blacklist IP từ mật khẩu sai.
3. Manual ban, ban Legacy có TTL và Authorized Ban V2 được thực thi tách biệt; khả năng tự hết hạn, unban và xử lý Redis lỗi có kiểm thử.
4. `security_correlator` đếm tín hiệu WAF đã gắn nguồn qua nhiều request/cửa sổ; chỉ phát hiện `SUSPICIOUS_SHADOW`, không biến quan sát thành quyền ban.
5. Nghiệm thu local E2E, rollback, regression và lưu chứng cứ truy xuất được đến commit.

**Ngoài phạm vi của PASS:** automatic ban production, chứng minh exploit thành công, xác minh độc lập nhiều nguồn, chứng minh một IP không thuộc NAT dùng chung, long-term audit, toàn bộ CSRF/P0.3, Jenkins CI/P0.4, benchmark/P0.7 và phát hành baseline P0.8.

## 3. Kiến trúc sau P0.2

**Luồng đăng nhập:** Client → OpenResty (trusted peer IP, rate limit, blacklist, WAF) → Django `/doLogin/` (CSRF + authenticate) → LoginAccounting V3 `admit/finalize` (khi flag ON) → Django session / HTTP result. Gateway xóa các internal headers `X-Login-Status`, `X-Login-Accounting`, `X-Login-Alert` trước khi trả về client.

**Luồng ban:** Security detector → Security Signal Adapter → Security Correlator (Shadow) → `verify()` **từ chối** vì thiếu xác minh độc lập/NAT. Tách biệt với nhánh issuer dành cho tương lai: verified evidence → `ip_ban_authorizer.lua` → `ip_ban_issuer.lua` → Redis `ban:v2:ip:<ip>` → `ip_blacklist.lua` → HTTP 403.

| Thành phần | Dữ liệu / chức năng | Ranh giới tin cậy |
|---|---|---|
| Login Accounting V3 | `bf:v3:*`, HMAC định danh tài khoản/nguồn, atomic `admit/finalize` | OFF mặc định; fail-closed khi không xác nhận được admission/finalization; không ban IP |
| `ip_ban_authorizer.lua` | Policy cấp ban tối đa 300 giây | Đòi bằng chứng exploit được xác minh + độc lập + đánh giá NAT mức ảnh hưởng thấp |
| `ip_ban_issuer.lua` | Redis `SET NX EX`, metadata và TTL cùng một giá trị | Gọi `correlator.verify()` và tự kiểm tra lại policy tại writer; không tin `approved=true` |
| `ip_blacklist.lua` | `blacklist_ips`, `blacklist:<ip>`, `ban:v2:ip:<ip>` | Manual/Legacy/V2 tách biệt; positive cache revalidate; negative cache tối đa 5 giây |
| `security_correlator.lua` | `ngx.shared.security_correlator_cache`, trạng thái shadow | Theo dõi WAF SQLi/XSS đã gắn nguồn; không phát hành IP ban |
| `security_shadow.lua` | Hook log-phase, gọi correlator | Quan sát không tác động HTTP; WAF bị chặn sớm vẫn được tính nếu WAF đã chạy hợp lệ |

**Ngưỡng thử nghiệm correlator:** ≥8 WAF-observed requests trong ≥3 buckets 60 giây, ≥2 class SQLi/XSS, xem trong 5 buckets gần nhất. Một request được tính tối đa một sự kiện; có dedup theo request ID. Lưu ý: 2 WAF classes không phải 2 nguồn độc lập.

## 4. Ma trận kết quả kiểm thử

| Hạng mục và bài kiểm thử | Kết quả được báo cáo | Điều đã chứng minh | Giới hạn |
|---|---|---|---|
| Gateway LuaJIT, `tests/run-unit.sh gateway` | **13 suites / 145 cases PASS** | Blacklist, issuer, correlator và các module security không phát hiện lỗi trong bộ unit | Mock/unit, không chứng minh toàn bộ production traffic |
| `test_security_correlator` | **23/23 PASS** (nằm trong 145) | Chống đếm trùng, tách IP, hạn chế cache, không giả mạo bằng chứng | Không phải độc lập nhiều nguồn |
| `test_ip_ban_issuer` | **12/12 PASS** (nằm trong 145) | Fail-closed, không tin approved giả, không gia hạn ban | Verified candidate có trong mock, không có correlator production |
| `test_authorized_ban_live.sh` | **10/10 PASS** | Redis TTL atomic, ban không bị gia hạn, HTTP 403 rồi trở về 200 | Sử dụng trực tiếp Redis EVAL với synthetic incident, không đi qua correlator thật |
| `test_blacklist_http_live.sh` | **13/13 PASS** | Manual ban/unban, Legacy TTL, HTTP enforcement, cache lifecycle | Local Docker client, không đo độ trễ ở quy mô lớn |
| `test_reputation_cas_live.sh` | **16/16 PASS** | Stale-write rejection, retry, tính toàn vẹn score/metadata, không đụng manual ban | Bộ test concurrency chọn lọc |
| `test_login_success_v3_e2e.sh` (tên tại checkpoint `4e7b350`; dự kiến đổi tên thành `test_successful_login_accounting_e2e.sh`) | **9/9 PASS ngày 21/11** | Tài khoản synthetic local, CSRF token, session, V3 success marker, chống giả `X-Real-IP`, rollback | Kết quả lịch sử thuộc source tại `4e7b350`; không mặc nhiên xem là kết quả chạy lại bản sau đổi tên/hardening |
| HTTP Correlator Shadow | **PASS: 8 events / 3 windows / 2 classes** | Tích lũy SQLi/XSS qua 3 khoảng thời gian; log `SUSPICIOUS_SHADOW` | `automatic_ban=disabled`; không chứng minh confirmed exploits |
| Feature flag và vận hành local | **3/3 Healthy; Correlator=false; V3=False** | Gateway/Redis/App healthy và rollback sau thử nghiệm | Snapshot ở thời điểm người dùng kiểm tra |
| Lua/HTTP NAT-aware V3 ở giai đoạn A3.3 | **Đã báo PASS ở checkpoint trước** | Tài khoản và nguồn được tính riêng; không tự khóa IP dùng chung | Cần bảo quản log gốc kèm hồ sơ nếu dùng trong luận văn |

**Không cộng 23/23 và 12/12 thêm vào 145/145:** đây là các nhóm con của Gateway Unit Regression. Các bài E2E độc lập cũng không nên cộng thành một “tỷ lệ kiểm thử toàn hệ thống” vì phạm vi và phương pháp khác nhau.

### 4.1. Bằng chứng Correlator thực tế

Các request local đều trả HTTP 403 do WAF; Docker logs xác nhận cả `[WAF][SQLi]` và `[WAF][XSS]`. Sau ba batch (22:17:26–27; 22:18:33; 22:19:39, ngày 21/11/2026), Gateway ghi:

```text
[SECURITY_CORRELATOR] status=SUSPICIOUS_SHADOW events=8 windows=3 classes=2 automatic_ban=disabled
```

Kiểm tra nhãn Docker Compose cho Gateway xác nhận `project=adaptive-security-local`, image `adaptive-security-gateway:local`, và port 80/443 chỉ bind `127.0.0.1`.

### 4.2. Sự cố phát hiện và hướng xử lý

- **`AppRegistryNotReady`**: Python `-c` trực tiếp chưa gọi Django setup trong script tạo/xóa test account. Khắc phục bằng `python manage.py shell -c`; sau đó Valid-Account E2E 9/9 PASS.
- **Correlator không phát log lúc đầu**: trong log-phase, `skipped_required` làm WAF event bị coi là incomplete khi JWT chưa chạy vì WAF đã chặn sớm. Sửa `partial` theo tình trạng bước WAF đã quan sát hợp lệ, giữ kiểm tra lỗi adapter/trace. Sau sửa, Correlator E2E PASS.
- **Đọc log sai nguồn**: đọc `error.log` trong container không ra bản ghi; `docker logs openresty_gateway` hiển thị log thực tế. Quy trình nghiệm thu dùng Docker logs.
- **Cảnh báo OCSP self-signed**: `ssl_stapling` warning trong local, `openresty -t` vẫn PASS; không phải bằng chứng TLS production đạt chuẩn.

## 5. Đánh giá điều kiện P0.2.1–P0.2.4

| Mốc | Đánh giá kỹ thuật đến 21/11/2026 | Ghi chú nghiệm thu |
|---|---|---|
| P0.2.1 – Django login signal | **PASS theo log regression giai đoạn trước** | `@require_POST`, authenticated/failed signals; V3 success E2E bổ sung bằng chứng |
| P0.2.2 – OpenResty login contract | **PASS trong phạm vi đã kiểm chứng**, còn cần tập hợp HTTP matrix vào hồ sơ | Header nội bộ không lộ, trust peer IP, `openresty -t`; log toàn bộ HTTP 405/403/302 cần bảo quản nếu yêu cầu nghiệm thu nguyên văn |
| P0.2.3 – Brute-force/account accounting | **PASS theo thiết kế NAT-Aware cập nhật** | IP lockout kiểu cũ không còn là mục tiêu: per-account/per-pair telemetry, bounded backoff, Redis atomic |
| P0.2.4 – Redis/E2E/ban/shadow | **PASS trong local scope** | Authorized ban, legacy blacklist, concurrency CAS, legitimate login và shadow correlation có bằng chứng; recovery/AOF cần giữ log riêng nếu dùng làm điều kiện bắt buộc |
| P0.2 tổng thể | **TECHNICAL ACCEPTANCE: PASS (LOCAL/SHADOW)** | **FORMAL CLOSURE: PENDING** cập nhật hồ sơ và đối chiếu các log còn thiếu theo checklist gốc |

Bản kế hoạch cũ trước mốc 21/11 có kỳ vọng IP-only lockout và trạng thái P0.2 chưa cập nhật; bản kế hoạch v2.1 đã điều chỉnh theo NAT-aware safety, bản v2.2 bổ sung nghiệm thu P0.3 (22/11). Không khôi phục IP-only lockout và không suy ra P0.2 FORMAL PASS chỉ từ việc đồng bộ tài liệu.

## 6. Rủi ro còn mở và giới hạn kết luận

| Mã | Rủi ro / hạn chế | Xử lý tiếp theo |
|---|---|---|
| R-01 | `security_correlator.verify()` luôn fail-closed vì thiếu verified exploit evidence và NAT assessment | Chỉ đánh giá/tương quan ở Shadow; giữ automatic issuance OFF; thiết kế bộ verifier sau khi có bằng chứng độc lập đáng tin |
| R-02 | Shadow Policy có thể báo khác biệt 403/503 khi WAF chặn trước JWT bắt buộc | Ghi nhận mismatch do short-circuit; bổ sung integration regression trong workstream policy, không thay đổi live enforcement tùy tiện |
| R-03 | Nội dung Shadow Correlator tại source `4e7b350` đã được phản ánh trong bản Markdown local | Chờ chủ dự án review và commit/push cùng hồ sơ P0.2; không đồng nghĩa automatic issuance được cho phép |
| R-04 | Kế hoạch v2.2 đã được chuẩn bị bổ sung trạng thái P0.3 và NAT-aware requirements | Chủ dự án cần review/commit/push bản tài liệu mới; P0.2 còn chờ historical HTTP method matrix và Redis recovery/AOF evidence |
| R-05 | Redis recovery/AOF, Jenkins trên commit mới, benchmark và thẩm định false positive chưa có log đầy đủ trong checkpoint này | Không tuyên bố PASS ngoài bằng chứng; thực hiện theo P0.4–P0.8 và checklist bổ sung |
| R-06 | WAF error logs có thể chứa request URI/query/payload nhạy cảm | P0.6: redaction, log format, retention và quyền truy cập; không đính kèm raw request chứa secrets |
| R-07 | Secret local đã được chia sẻ ngoài file `.env.local`; chưa có bằng chứng rotation | Rotate khi thích hợp, không đưa vào Git/log/report; thay mật khẩu MySQL cùng state database, không chỉ sửa env |
| R-08 | Negative cache blacklist có cửa sổ nhìn thấy ban mới tối đa 5 giây | Giữ trong threat model; đo và ghi rõ khi đánh giá mitigation latency |

## 7. Kết luận nghiệm thu và quyết định dự án

**Kết luận kỹ thuật:** P0.2 hoàn tất chức năng và thử nghiệm cốt lõi trong local lab tại checkpoint `4e7b350` với Rule-Based, NAT-Aware Login Accounting, Authorized Ban storage và Correlator Shadow; không quan sát lỗi hồi quy trong những bộ test được báo cáo. P0.3 đã được nghiệm thu kỹ thuật local riêng tại checkpoint `b510488` (tài liệu P0.3 tại `7c51a35`); kết quả này không thay thế các gate lịch sử còn mở của P0.2.

**Kết luận hồ sơ:** Chưa phát hành tuyên bố “P0.2 chính thức đóng, sẵn sàng production”. Trước khi cập nhật bảng trạng thái dự án, cần đồng bộ hai tài liệu, lưu bằng chứng E2E/bảng HTTP method nếu có, kiểm tra log recovery mà kế hoạch yêu cầu và chốt giới hạn Shadow-only. Không gộp với kết quả P0.3–P0.8.

**Quyết định hiện tại:** `P0.2 = TECHNICAL PASS (LOCAL/SHADOW) / FORMAL PENDING` cho tới khi owner đối chiếu HTTP method/status matrix và Redis recovery/AOF theo checklist gốc. Có thể tiếp tục P0.4–P0.8; **P0.3 đã LOCAL TECHNICAL ACCEPTANCE PASS**, không cho phép automatic ban hoặc buộc bật V3 ở production.

## 8. Danh mục bằng chứng và cách tái hiện

### 8.1. Các tập tin nguồn trọng yếu tại commit `4e7b350`

- `nginx/lua/security_signal_adapter.lua`, `nginx/lua/security_shadow.lua`, `nginx/lua/security_correlator.lua`
- `nginx/lua/ip_ban_authorizer.lua`, `nginx/lua/ip_ban_issuer.lua`, `nginx/lua/ip_blacklist.lua`
- `docappsystem/docappsystem/login_accounting.py`, `docappsystem/docappsystem/views.py`
- `nginx/tests/test_security_correlator.lua`, `nginx/tests/test_ip_ban_issuer.lua`, `nginx/tests/test_authorized_ban_live.sh`
- `nginx/tests/test_login_success_v3_e2e.sh` (**tên ở checkpoint lịch sử `4e7b350`; bản làm việc mới đặt `test_successful_login_accounting_e2e.sh`**), `nginx/tests/test_blacklist_http_live.sh`, `nginx/tests/test_reputation_cas_live.sh`
- `tests/run-unit.sh`, `tests/run-integration.sh`, `scripts/audit_legacy_bans.py`
- `docs/SECURITY_CORRELATOR.md`, `docs/Ke_hoach_tong_the_ASG_ML.md`

### 8.2. Lệnh tái hiện tại môi trường local được ủy quyền

```bash
# Unit regression
bash tests/run-unit.sh gateway

# Redis / HTTP acceptance: chỉ chạy tại local lab
bash nginx/tests/test_authorized_ban_live.sh
bash nginx/tests/test_blacklist_http_live.sh
bash nginx/tests/test_reputation_cas_live.sh

# Valid login E2E: tạo/xóa user synthetic, tạm recreate app/gateway
# Chỉ chạy sau khi xác minh môi trường local và cờ V3 OFF
bash nginx/tests/test_successful_login_accounting_e2e.sh

# Phân định phiên bản checkpoint
git rev-parse HEAD
git status --short
```

**Điều kiện an toàn:** `docker-compose.dev.yml`, HTTPS gateway bind loopback, DB local, test clients tách biệt, không `FLUSHDB`, không xóa key theo prefix, không chạy E2E có side effects trên shared/production. Bản script mới đổi tên có thể có thêm runtime guard/cleanup hardening; trước khi coi là kiểm thử lại phải chạy và lưu log trên local. Correlator Shadow dùng payload synthetic và rollback `SECURITY_CORRELATOR_SHADOW_ENABLED=false` sau thử nghiệm.

### 8.3. Liên kết tham chiếu cố định

- Commit A3.4: https://github.com/NTNguyen055/Adaptive-Security-Gateway/commit/4e7b350
- Branch: https://github.com/NTNguyen055/Adaptive-Security-Gateway/tree/feature/p0-security-baseline
- Correlator source: https://github.com/NTNguyen055/Adaptive-Security-Gateway/blob/4e7b350/nginx/lua/security_correlator.lua
- Policy Authorizer: https://github.com/NTNguyen055/Adaptive-Security-Gateway/blob/4e7b350/nginx/lua/ip_ban_authorizer.lua
- Report scope: local testing outputs furnished by project owner on 21/11/2026; not a GitHub CI artifact.

## 9. Đồng bộ hồ sơ sau nghiệm thu P0.3 (22/11/2026)

**Không tự sửa GitHub:** Chủ dự án tự thay các file sau khi review, commit/push. Báo cáo này đặt tại **`docs/P0_2_SECURITY_ACCEPTANCE_2026-11-21.md`**, không phải `docs/reports/`.

1. **`docs/SECURITY_CORRELATOR.md`:** giữ source checkpoint `4e7b350`, cập nhật đúng Shadow E2E PASS và guard `partial` thực tế; giữ `verify()` fail-closed, nêu rõ Docker logs và giới hạn Shadow-only.
2. **`docs/Ke_hoach_tong_the_ASG_ML.md`:** cập nhật v2.2, P0.3 local PASS tại `b510488`/docs `7c51a35`, P0.2 formal pending do hai nhóm evidence lịch sử.
3. **`nginx/tests/test_successful_login_accounting_e2e.sh`:** đổi tên từ `test_login_success_v3_e2e.sh`. Nếu chỉ rename nguyên trạng, 9/9 vẫn là bằng chứng lịch sử; nếu hardening script, phải chạy lại trong local có guard và cleanup để xác nhận phiên bản mới.
4. **P0.2 formal closure gate:** thu thập/đối chiếu HTTP method/status matrix P0.2 và Redis recovery/AOF theo checklist gốc; không lấy P0.3 HTTPS tests thay cho các log yêu cầu riêng.
5. **Evidence preservation:** lưu log đã che dữ liệu cá nhân, SHA và config snapshots không chứa secrets; không ghi tăng số bài kiểm thử hoặc tự bật automatic IP ban.

**Review giá trị khoa học:** P0.2 tạo baseline có thể tái hiện cho so sánh các chính sách phản ứng Layer 7 về sau: đếm theo tài khoản/nguồn, giới hạn ảnh hưởng NAT, state atomic/TTL, ranh giới authorization và tương quan WAF Shadow. Nó **không** phải bằng chứng hiệu năng, tỷ lệ false positive toàn diện, hay tác dụng của mô hình Machine Learning.
