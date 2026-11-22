# P0.3 — CSRF & Authentication Request Security
## Báo cáo nghiệm thu kỹ thuật (Local Security Lab)

**Dự án:** AdaptiveSecurityGW + Machine Learning for Layer 7
**Nhánh phát triển:** `feature/p0-security-baseline`
**Ngày kiểm thử:** 2026-11-22 (Asia/Ho_Chi_Minh)
**Phiên bản/commit được nghiệm thu:** `PENDING_COMMIT_HASH`
**Trạng thái:** **TECHNICAL TESTS PASS — FORMAL ACCEPTANCE PENDING SOURCE/DIFF AUDIT & GIT CHECKPOINT**
**Môi trường:** Docker Compose local; HTTPS `https://localhost` qua OpenResty; Django; MySQL; Redis. Không sử dụng staging/production.

> Báo cáo tổng hợp những kết quả người thực hiện đã cung cấp qua terminal. Không có tuyên bố rằng bên review trực tiếp chạy Docker trên máy người thực hiện. Số lượng Django regression đã bao gồm các bộ unit test thành phần; không cộng lặp để quảng bá thành số test độc lập.

## 1. Mục tiêu và phạm vi

1. **CSRF protection:** bắt buộc token hợp lệ cho unsafe methods; kiểm tra Origin/Referer với HTTPS, từ chối cross-origin.
2. **Authentication request methods:** chỉ chấp nhận methods phù hợp từng endpoint; `/logout/` POST-only, bảo toàn session khi logout bị từ chối.
3. **Role & authorization:** custom Admin (`user_type="1"`) và Doctor (`user_type="2"`) không vượt quyền; không đồng nhất custom role với Django Admin `is_staff`.
4. **Proxy trust boundary:** không chấp nhận các forwarded/identity headers giả từ client làm suy yếu xử lý CSRF hoặc web-session authorization trong các tình huống kiểm thử.
5. **HTTP method inventory:** quy định GET/HEAD, GET-only, GET/POST, POST-only cho các endpoint do ứng dụng quản lý; không tự ý áp đặt chính sách của ứng dụng lên Django Admin tích hợp.

## 2. Các thay đổi đã quan sát qua local `git diff`

| Tệp | Nội dung thay đổi được review |
|---|---|
| `docappsystem/docappsystem/settings.py` | `CSRF_TRUSTED_ORIGINS` lấy từ env explicit, mặc định `[]`; `USE_X_FORWARDED_HOST=False`, `USE_X_FORWARDED_PORT=False`; vẫn duy trì `SECURE_PROXY_SSL_HEADER` |
| `docappsystem/docappsystem/urls.py` | Bọc Django `LogoutView` bằng `require_POST` |
| `docappsystem/docappsystem/views.py` | Method restrictions với BASE, LOGIN, PROFILE, CHANGE_PASSWORD; doLogin POST-only đã có |
| `docappsystem/docappsystem/userviews.py` | GET/HEAD cho read-only; GET/POST cho appointment form |
| `docappsystem/docappsystem/adminviews.py` | Role guard giữ nguyên; thêm `require_safe` và GET-only cho Search_Doctor |
| `docappsystem/docappsystem/docviews.py` | Role/ownership guard giữ nguyên; thêm `require_safe` và GET-only cho Search_Appointments |
| `docappsystem/templates/includes/header.html` | Có thay đổi local, **diff chính xác chưa được cung cấp cho bước audit cuối**; bản E2E chứng minh form logout hoạt động trong những trường hợp đã thử |
| `.env.example` | Có thay đổi local, **diff chưa được cung cấp cho bước audit cuối** |

**Ranh giới chứng cứ:** Từ các diff đã dán có thể đánh giá sáu tệp Python ở trên; không thể xác nhận chữ-by-chữ nội dung các tệp còn lại chưa được cung cấp. Local files untracked không hiển thị trong `git diff` thông thường.

## 3. Bằng chứng kiểm thử

| Mã | Nhóm | Kết quả đã nhận | Phương pháp/giới hạn |
|---|---|---|---|
| P03-UT-01 | Django CSRF & Auth | 20/20 PASS | Django test client; đã nằm trong regression tổng |
| P03-UT-02 | HTTP Method & Role Matrix | 14/14 PASS | Django test client; đã nằm trong regression tổng |
| P03-UT-03 | HTTP Method Inventory | 16/16 PASS | Django test client, SQLite in-memory; đã nằm trong regression tổng |
| P03-REG-01 | Django full offline regression | **114 discovered / 102 executed PASS / 12 skipped / 0 FAIL** | Redis live tests bị skip có chủ đích, không được tính PASS |
| P03-GW-01 | Gateway LuaJIT offline regression | **145/145 PASS** | Kết quả trước đó; mocked/offline, không phải full HTTPS E2E |
| P03-E2E-01 | Authenticated HTTPS security flow | **37 checkpoints PASS / 0 FAIL** | HTTPS → OpenResty → Django → session và DB local; kết quả trước lần hardening inventory cuối |
| P03-E2E-02 | Proxy Trust HTTPS Matrix | **19 checkpoints PASS / 0 FAIL** | HTTPS local; kiểm tra Origin, forwarded headers, forged identity; kết quả trước lần hardening inventory cuối |
| P03-E2E-03 | Admin/Doctor HTTPS Sessions | **36 checkpoints PASS / 0 FAIL** | Hai role, login/dashboard/cross-role/logout, fixture tạo và dọn đúng tại local sau hardening inventory |

**Dấu hiệu cuối trong log ngày 2026-11-22:**

```text
HTTP METHOD INVENTORY: Ran 16 tests ... OK
DJANGO REGRESSION: Found 114 test(s); Ran 114 tests ... OK (skipped=12)
LOCAL ADMIN/DOCTOR HTTPS E2E: 36 passed, 0 failed
LOCAL ADMIN/DOCTOR FIXTURES: REMOVED
```

*Các dòng trên là bản rút gọn trình bày để tổng hợp; giữ log gốc đầy đủ làm chứng cứ và đối chiếu khi nộp báo cáo.*

## 4. RED → GREEN: tính truy vết lỗi

| Giai đoạn | RED baseline | Chính sách khắc phục | GREEN |
|---|---|---|---|
| Read-only sample (4 routes) | 4 subtests FAIL; PUT được render 200 thay vì 405 | `@require_safe` | 2 test methods và 4 subtests GREEN trong regression |
| Extended inventory (22 views) | 11 test methods; 100 assertion FAIL, 12 ERROR. Nhiều method trên một view tạo nhiều subtest results | 20 read-only views: `@require_safe`; 2 GET-only search views: `@require_http_methods(["GET"])` | 16/16 test methods PASS; 0 FAIL/ERROR |

Các 12 ERROR trước patch là `ValueError: ... didn't return an HttpResponse object. It returned None instead` khi search view nhận method không hỗ trợ. Số lượng FAIL/ERROR không tương đương số lỗ hổng độc lập.

## 5. Đánh giá phòng thủ nhiều tầng

- **Method boundary:** request sai method bị 405 tại Django view trong các endpoint đã đo.
- **CSRF boundary:** POST thiếu/sai CSRF, cross-origin, HTTPS không có Origin/Referer được Django CSRF layer từ chối trong các tình huống đã kiểm tra.
- **Session boundary:** GET logout và POST logout không hợp lệ không hủy session; POST logout hợp lệ hủy session.
- **Role boundary:** Admin/Doctor dùng session riêng; truy cập dashboard sai role bị 403; forged identity headers không thay thế role của session đang dùng.
- **Django Admin separation:** `user_type="1"` không tự cấp `is_staff`; custom Admin/Doctor non-staff không truy cập được Django Admin trong kịch bản thử.
- **Proxy trust boundary:** `X-Forwarded-Proto` giả không bỏ qua HTTPS CSRF; giả Host được từ chối trong tình huống thử. Chưa khẳng định mọi header bị xóa trên mọi proxy location nếu chưa có log quan sát trực tiếp.

## 6. Giới hạn nghiệm thu

1. **Local, không phải production:** HTTPS qua localhost, curl `-k` bỏ qua xác minh CA. Không suy rộng trực tiếp sang DNS/TLS certificate hoặc deployment production.
2. **Django isolated regression:** dùng SQLite in-memory; 12 Redis live test vẫn skipped, không phải lỗi và cũng không được tính đã kiểm thử.
3. **Unit/LuaJIT vs E2E:** 145 Gateway cases dùng kiểm thử offline; ba nhóm E2E kiểm tra request thực qua HTTPS nhưng không đại diện cho mọi attack path.
4. **Không phải browser automation:** kiểm tra form HTML và cookie jar qua curl, chưa có Selenium/Playwright; phù hợp mục tiêu security HTTP E2E đã định nghĩa.
5. **Quản lý chứng cứ:** chưa nhận được `git diff` đúng đường dẫn của `header.html`, `.env.example`, `git diff --cached` đối với rename P0.2 hoặc các thay đổi local docs để audit cuối.
6. **P0.2 backlog:** HTTP method matrix historical evidence / Redis recovery-AOF và hồ sơ P0.2 là các đầu việc riêng, không được mặc nhiên chốt bởi PASS P0.3.

## 7. Tiêu chí đóng nghiệm thu kỹ thuật P0.3

- [x] CSRF/Auth unit tests PASS.
- [x] Role & HTTP Method Matrix PASS.
- [x] Extended HTTP Method Inventory chuyển RED → GREEN.
- [x] Django offline regression PASS; skips được giải thích.
- [x] Authenticated HTTPS E2E, Proxy Trust HTTPS E2E và Admin/Doctor HTTPS E2E PASS theo log đã cung cấp.
- [x] Không có lỗi runtime/fixture cleanup được ghi nhận trong Admin/Doctor HTTPS E2E.
- [ ] Audit diff local chính xác cho `.env.example` và `docappsystem/templates/includes/header.html`.
- [ ] Audit git staging để không lẫn rename và tài liệu P0.2 vào commit P0.3.
- [ ] Ghi commit hash chứa đầy đủ source/test/docs P0.3, sau đó kiểm tra Git remote push và working tree.
- [ ] Nếu muốn một mốc E2E cùng image sau hardening inventory, chạy lại smoke 37 và proxy 19 trước khi ghi dấu nghiệm thu cuối (khuyến nghị, không thay thế những kết quả đã PASS).

## 8. Khuyến nghị Git checkpoint

**Không dùng `git add .` vì workspace đang có P0.2 docs và rename đã stage.**

Gợi ý cấu trúc checkpoint:

1. Commit P0.3 riêng: sáu source Python, đúng `header.html`, `.env.example`, ba Django tests, ba HTTPS E2E scripts, inventory Markdown này và báo cáo nghiệm thu.
2. Commit P0.2 docs/maintenance riêng (sau review): `SECURITY_CORRELATOR.md`, `Ke_hoach_tong_the_ASG_ML.md`, `P0_2_SECURITY_ACCEPTANCE_2026-11-21.md`, script rename.
3. Push nhánh `feature/p0-security-baseline` sau khi xác minh chỉ có các commit mong muốn.

**Commit hash:** `PENDING_COMMIT_HASH`
**Git remote:** `PENDING_REMOTE_VERIFICATION`
**Người nghiệm thu:** `PENDING_USER_REVIEW`
**Kết luận cuối:** **PENDING FINAL AUDIT**. Các tiêu chí kiểm thử kỹ thuật đã đạt trong phạm vi Local Security Lab.
