# Bộ file khởi động Giai đoạn 1.1 — Adaptive Security Gateway

Dùng để **thêm** cấu hình local vào repository https://github.com/NTNguyen055/Adaptive-Security-Gateway mà **không thay thế** `docker-compose.yml` và `settings.py` production.

## Các bước

1. Clone repository của bạn về máy (hoặc sử dụng bản clone đang có).
2. Sao chép **các thư mục/file trong ZIP** vào đúng đường dẫn tương ứng của repository. Giữ nguyên cấu trúc thư mục; không sao chép đè production files.
3. Mở `docs/LOCAL_DEVELOPMENT.md` và làm theo hướng dẫn.
4. Sau khi chạy, gửi lại trạng thái containers và các dòng lỗi **đã loại bỏ thông tin nhạy cảm**, nếu có; chúng ta sẽ sửa tiếp.

## File mới

- `docker-compose.dev.yml`: local Compose độc lập (MySQL, Redis, Django, OpenResty, monitoring tùy chọn).
- `.env.local.example`: khuôn mẫu không chứa secret thật.
- `scripts/init-local-env.py`: sinh secret ngẫu nhiên vào `.env.local`.
- `docappsystem/docappsystem/settings_local.py`: cấu hình Django chỉ dành cho local.
- `docs/LOCAL_DEVELOPMENT.md`: hướng dẫn chạy và xử lý lỗi.

**Chú ý:** Các file này là bản chuẩn bị cấu hình và đã qua kiểm tra cú pháp tĩnh; chưa được chạy end-to-end với Docker. Bước đầu của Giai đoạn 1 sẽ chỉ được đánh dấu hoàn thành khi container thực sự healthy và các chức năng cơ bản hoạt động trên máy của bạn.
