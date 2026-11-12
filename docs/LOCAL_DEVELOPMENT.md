# Giai đoạn 1.1 — Chạy Adaptive Security Gateway trên máy local

> **Chỉ dành cho môi trường lab.** Không sử dụng `docker-compose.dev.yml` để công khai dịch vụ lên Internet. Nhánh production (`docker-compose.yml`) được giữ nguyên.

## Yêu cầu

- Docker Desktop đã bật Docker Compose v2 (Windows/WSL2, macOS hoặc Linux).
- Python 3 để tạo `.env.local` (không cần cài thư viện bên ngoài).
- Docker được cấp đủ tài nguyên, đề xuất khoảng 4–6 GB RAM cho toàn bộ stack local và bộ nhớ/ổ cứng còn trống để build image.
- Port **80** và **443** trên máy chưa bị ứng dụng khác chiếm. Các port chỉ bind `127.0.0.1`.

## Cài đặt

Từ thư mục gốc repository (nơi có `nginx/`, `docappsystem/`):

```bash
python scripts/init-local-env.py

docker compose --env-file .env.local -f docker-compose.dev.yml config --quiet

docker compose --env-file .env.local -f docker-compose.dev.yml up -d --build

docker compose --env-file .env.local -f docker-compose.dev.yml ps
```

`settings_local.py` dùng MySQL nội bộ ở service `db`, không cần AWS RDS. Django chạy `migrate`, `collectstatic`, sau đó Gunicorn; Gateway build từ `nginx/Dockerfile`, dùng cấu hình Lua hiện có.

**Lưu ý chứng chỉ:** `nginx/Dockerfile` chứa chứng chỉ **tự ký tạm thời** cho lần khởi động ban đầu. Nó không phù hợp với hostname `localhost`, nên trình duyệt có thể cảnh báo chứng chỉ. Chỉ bỏ qua xác minh chứng chỉ trong môi trường local và KHÔNG dùng cấu hình này trong production.

```bash
curl -k https://localhost/health/
```

Nếu Windows PowerShell gọi `curl`, có thể dùng `curl.exe -k https://localhost/health/`.

Bạn có thể thử `https://localhost/login/` trên trình duyệt local (chấp nhận cảnh báo self-signed trong lab). Truy cập cổng HTTP `http://localhost/` sẽ được redirect sang HTTPS.

## Logs và chẩn đoán

```bash
docker compose --env-file .env.local -f docker-compose.dev.yml logs -f app db redis

docker compose --env-file .env.local -f docker-compose.dev.yml exec gateway sh -c 'tail -n 60 /usr/local/openresty/nginx/logs/error.log'

docker compose --env-file .env.local -f docker-compose.dev.yml exec app python manage.py check

docker compose --env-file .env.local -f docker-compose.dev.yml exec db mysql -u adaptive_user -p adaptive_gateway_dev
```

Dòng cuối sẽ yêu cầu password; tìm **chỉ trên máy của bạn** trong `.env.local` (không gửi cho người khác). Cơ sở dữ liệu chưa có dữ liệu mẫu nên các trang phụ thuộc vào bản ghi mẫu có thể hiển thị rỗng.

## Bật monitoring (tùy chọn)

```bash
docker compose --env-file .env.local -f docker-compose.dev.yml --profile monitoring up -d
```

Prometheus tại `http://localhost:9090` và Grafana tại `http://localhost:3000`. Tài khoản Grafana: `admin` và mật khẩu trong `.env.local`.

## Dừng / xóa dữ liệu

```bash
docker compose --env-file .env.local -f docker-compose.dev.yml down
```

Lệnh trên **giữ lại** MySQL và volume logs. Để xóa toàn bộ dữ liệu local (không thể phục hồi), chạy `down -v` nhưng hãy sao lưu trước nếu đã tạo dữ liệu kiểm thử.

## Những việc chưa được giải quyết bởi gói 1.1

- Chưa sửa authorization cho các Django admin views, identity header spoofing, rate limiting, IP blacklist hoặc risk policies. Đây là các hạng mục 1.2–1.7.
- `nginx.conf` vẫn có hostname `asg-datn.duckdns.org` cho production và file cert tự ký chỉ được dùng ở local; không dùng để đánh giá TLS production.
- `settings.py` production hiện có cấu hình TLS MySQL cần kiểm tra lại; `settings_local.py` sửa riêng đường kết nối MySQL local bằng `ssl_mode=DISABLED`.
- Không có điều kiện chạy Docker daemon trong môi trường chuẩn bị gói file này, vì vậy **chưa xác nhận hệ thống chạy thành công bằng integration test**. Hãy đối chiếu `ps` và logs sau khi chạy.
- Nếu Docker báo không bind được 80/443, cần giải phóng port hoặc điều chỉnh Nginx redirect phù hợp khi đổi port host.
