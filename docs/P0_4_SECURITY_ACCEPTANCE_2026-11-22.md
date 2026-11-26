# P0.4 — CI & Regression Pipeline
## Báo cáo nghiệm thu kỹ thuật (Jenkins PR Pipeline + Local Negative Contract)

**Dự án:** AdaptiveSecurityGW + Machine Learning for Layer 7  
**Ngày nghiệm thu:** 22/11/2026 (Asia/Ho_Chi_Minh)  
**Phạm vi:** CI kiểm thử Rule-Based Security Baseline trước khi mở rộng P0.5–P0.8 và Machine Learning  
**Kết luận:** **P0.4 TECHNICAL ACCEPTANCE — PASS**  
**Đóng hồ sơ Git:** Cần thêm báo cáo này và `tests/test-ci-fail-closed.sh` vào repository sau khi review; không yêu cầu lặp lại Jenkins build đã PASS nếu chỉ thêm bằng chứng độc lập và không sửa pipeline.

> Phân biệt bằng chứng: (1) file `ci-unit.log` đã tải trực tiếp từ Jenkins Build Artifacts và được kiểm tra nội dung; (2) Console Output Jenkins được người thực hiện cung cấp; (3) các GitHub Checks được đối chiếu trên GitHub; (4) negative test được người thực hiện chạy ở local, không phải Jenkins failure-injection run. Không suy rộng kết quả CI offline thành bằng chứng production hoặc full integration E2E.

## 1. Mục tiêu nghiệm thu

1. Ngăn CI thiếu các suite Lua có trong repository; danh sách local và Jenkins phải tương đương.
2. Build App/Gateway image từ chính source revision đang kiểm thử; Unit Regression chạy bằng image vừa build.
3. Đảm bảo Lua Security Policy, ban authorization, correlator/shadow, risk/TTL, NAT-aware brute-force và Django authentication security có hồi quy tự động.
4. Xử lý lỗi kiểm thử theo nguyên tắc fail-closed: exit code hoặc output không hợp lệ không được biến thành kết quả PASS.
5. Ghi và lưu CI artifact để tái kiểm chứng; giữ release isolation trên pull request/feature branch.

## 2. Nguồn kiểm thử và môi trường

| Thuộc tính | Giá trị đã xác minh |
|---|---|
| Source revision được Jenkins checkout | `8786e191955f6087ed0ca6f6ccf63251c7f5dc54` |
| Jenkins job | `asg-multibranch / PR-29 / #1` |
| Pull request | `#29`, từ `feature/p0-security-baseline` sang `develop` (chưa merge khi kiểm tra) |
| Build result | `Finished: SUCCESS` |
| Jenkins run URL | `https://jenkins-datn.duckdns.org/job/asg-multibranch/job/PR-29/1/` |
| Build images | App và OpenResty Gateway; tag CI `ci-PR-29-1-8786e191955f` |
| CI mode | Offline LuaJIT mock regression và Django isolated test database; không truy cập MySQL/Redis production |
| Artifact | `ci-unit.log` tải được từ Build Artifacts |
| Artifact byte size | `43,349` bytes |
| Artifact SHA-256 | `e22499f02a4752a11818c75fdf31aa9769d4314d91a0e9858dec2a9a94baf348` |

SHA-256 ở trên xác định đúng bản artifact đã đối chiếu; không dùng commit SHA của nhánh làm trường trạng thái thường xuyên phải cập nhật.

## 3. Jenkins acceptance matrix

| Gate | Bằng chứng | Kết quả |
|---|---|---|
| P0.4.1 — Suite parity | `PASS: Local/CI Lua suite parity (18 suites, all Lua tests accounted for)` | **PASS** |
| P0.4.2 — Build Images | App và Gateway được build thành công từ revision chỉ định | **PASS** |
| P0.4.2 — LuaJIT offline regression | **18 suites / 299 cases PASS / 0 failed** | **PASS** |
| P0.4.2 — Django isolated regression | **114 tests discovered / 102 PASS / 12 skipped / 0 failed** | **PASS (12 skipped ghi riêng)** |
| P0.4.3 — OpenResty smoke | `openresty -t`: syntax và config test successful | **PASS** |
| P0.4.3 — Lua dependencies | `[SMOKE] Gateway Lua dependencies OK` | **PASS** |
| P0.4.3 — Docker workspace bind mapping | CI đã thực thi 18 test suites bằng Docker images mới build và read-only Lua mounts | **PASS trong Jenkins job này** |
| P0.4.3 — Archive | Jenkins `Archiving artifacts`; file `ci-unit.log` thực tế tải được, có nội dung hợp lệ | **PASS** |
| P0.4.3 — Release isolation | 6 stage publish/deploy bị bỏ qua bởi `when` condition ở PR-29 | **PASS** |
| P0.4.4 — Runner negative contract | 5 local cases: 1 positive, 4 negative | **PASS (local mock, không phải Jenkins failure-injection)** |
| GitHub reporting | 12 Check Runs: 6 success, 6 skipped; Jenkins `pr-head` commit status success | **PASS** |

**Chi tiết số lượng thành công trên GitHub:** Giao diện báo *7 successful checks* gồm **6 GitHub Check Runs SUCCESS và 1 Jenkins commit status SUCCESS**. Không cộng thành 13 Check Runs.

## 4. Security regression coverage theo `ci-unit.log`

| Lua suite | Cases PASS |
|---|---:|
| `test_ip_blacklist` | 22 |
| `test_ip_ban_authorizer` | 24 |
| `test_ip_ban_issuer` | 12 |
| `test_security_correlator` | 23 |
| `test_security_policy` | 47 |
| `test_security_shadow` | 23 |
| `test_security_signal_adapter` | 55 |
| `test_telegram_alert` | 5 |
| `test_brute_force_login` | 16 |
| `test_jwt_auth` | 12 |
| `test_metrics_labels` | 9 |
| `test_rate_limit` | 5 |
| `test_rate_limit_redis` | 7 |
| `test_rate_only_guard` | 7 |
| `test_risk_decay` | 8 |
| `test_risk_engine` | 8 |
| `test_risk_redis_failure` | 11 |
| `test_risk_reputation_ttl` | 5 |
| **Tổng** | **299** |

**Ý nghĩa bảo mật:** Regression bảo toàn các hợp đồng: không tự nâng risk/ML signal thành IP ban, xác thực nguồn security signals, NAT-aware accounting, Redis failure handling, TTL/decay, request-only blocking, shadow không can thiệp live enforcement và kiểm thử Telegram không gửi request thật.

**Django:** `Found 114 test(s)` và `OK (skipped=12)`. Các dòng 403/405/429/503, mock Redis errors và CSRF warnings thuộc các tình huống kiểm thử âm tính; không phải regression FAIL vì test runner kết thúc `OK`. Mười hai test được skip không được tính thành PASS hoặc thay thế bằng giả định.

## 5. Negative testing — Fail-closed CI runner

**Script:** `tests/test-ci-fail-closed.sh` (local, cần lưu vào Git để tái lập).  
**Thiết kế:** Sao chép `tests/run-ci.sh` sang thư mục tạm, dùng Docker CLI giả lập, không chạy Docker daemon, không truy cập dịch vụ thật.  
**Kết quả người thực hiện cung cấp:**

```text
PASS  ok                expected=pass actual_exit=0
PASS  summary_failure   expected=fail actual_exit=1
PASS  nonzero_exit      expected=fail actual_exit=1
PASS  missing_summary   expected=fail actual_exit=1
PASS  zero_cases        expected=fail actual_exit=1
P0.4 isolated CI runner contract: 5 passed, 0 failed
```

**Giải thích:** Bốn trường hợp bất thường phải kết thúc bằng exit code khác 0, không được in kết quả thành công cuối cùng. Trường hợp hợp lệ có exit code 0. Jenkinsfile có cơ chế `exit 1` khi `tests/run-ci.sh` thất bại, nhưng chưa cố ý tạo một Jenkins build RED để kiểm chứng hành vi đó end-to-end.

## 6. Release isolation, artifact và tính tái lập

- PR-29 chỉ chạy Checkout, Pre-build Checks, Build Images, Unit Regression, Smoke Test; các bước DockerHub production/develop publish, migration, deploy AWS và publish latest được bỏ qua.
- CI LuaJIT chạy trong container với `--network none`, source/test bind mount read-only; Telegram sử dụng dummy credentials và mocked HTTP. Django isolated regression sử dụng in-memory SQLite và test cache, không phải integration test với Redis/MySQL thật.
- Jenkins đã tạo `ci-unit.log`, in nội dung lên console và archive artifact. File do người thực hiện tải về là bằng chứng độc lập với bản console paste.
- Không đưa nguyên file `ci-unit.log` vào source Git nếu không có chính sách lưu log riêng; giữ artifact ở Jenkins và ghi SHA-256/path trong báo cáo.
- Repo có suite parity checker, local runner, CI runner và negative test để tái lập logic kiểm thử ở thời điểm mới.

## 7. Giới hạn và risk register

1. **Không phải production acceptance:** Jenkins build chạy offline unit/mocked tests, chưa đo p95/p99, FPR/FNR, tải thực hay khả năng chịu lỗi end-to-end; các mục này thuộc P0.5–P0.8/P5.
2. **12 Django skipped:** Đây không phải 12 test PASS. Các Redis live integration tests cần được đánh giá riêng bằng môi trường cô lập và được đối chiếu trong hồ sơ P0.2/P0.5.
3. **Negative testing giới hạn runner:** Đã kiểm tra thực thi fail-closed của runner bằng mock; chưa thực hiện Jenkins failure-injection PR build. Không giả định Jenkins tự động thông qua mọi dạng lỗi hoặc thử nghiệm policy ngoài phạm vi.
4. **TLS smoke:** Log `openresty -t` có warning `ssl_stapling ignored` với certificate build giả lập một ngày; không làm fail Nginx syntax, nhưng cũng không chứng minh OCSP/certificate chain đúng trong production.
5. **PR chưa merge:** PR #29 có CI PASS, không suy ra rằng cần merge ngay hoặc tự động triển khai. Tiếp tục phát triển P0.5–P0.8 trên feature branch theo quy trình review của dự án.
6. **P0.2 formal backlog độc lập:** HTTP method/status matrix lịch sử và Redis recovery/AOF vẫn phải đối chiếu trước khi kết luận P0.2 formal acceptance. P0.4 PASS không đóng thay các gate đó.

## 8. Kết luận nghiệm thu và giá trị nghiên cứu

**Kết luận:** **P0.4 TECHNICAL ACCEPTANCE PASS** ở đúng phạm vi Jenkins CI/Regression, artifact và negative runner contract đã nêu. Không có lỗi bảo mật hoặc lỗi pipeline hiện biết nào từ các bằng chứng đã kiểm tra buộc phải mở lại source P0.4.

**Giá trị bổ sung:**
- Đưa 18 Lua suites / 299 cases và Django isolated regression vào Jenkins, tránh bỏ sót các security contract tests quan trọng.
- Có parity guard ngăn một Lua test mới âm thầm nằm ngoài regression pipeline.
- Chứng minh code đang kiểm thử được build và chạy trên CI image tương ứng, có log xuất bản và truy xuất được.
- Bảo vệ feature/PR branch khỏi side effects phát hành và triển khai; hạn chế false-green khi test runner gặp lỗi.
- Cung cấp nền kiểm thử tái lập để tiếp tục P0.5 Risk/TTL/Policy, P0.6 WAF Privacy, P0.7 Benchmark và P0.8 Baseline Ready, sau đó đánh giá ML/Adaptive.

**Bước quản trị bằng chứng tiếp theo:** Review/stage riêng 2 file `docs/P0_4_SECURITY_ACCEPTANCE_2026-11-22.md` và `tests/test-ci-fail-closed.sh`, commit/push khi `git diff --cached --check` PASS. Không sửa lại source P0.4 đã nghiệm thu chỉ để cập nhật thông tin nhánh.
