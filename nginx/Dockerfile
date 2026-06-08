FROM openresty/openresty:alpine-fat

# Thêm chuẩn OCI Labels để dễ dàng truy vết (Traceability)
ARG BUILD_DATE
ARG COMMIT_SHA
ARG VERSION

LABEL org.opencontainers.image.title="Adaptive Security Gateway" \
      org.opencontainers.image.description="OpenResty WAF & Security Gateway" \
      org.opencontainers.image.authors="NTNguyen055" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${COMMIT_SHA}" \
      org.opencontainers.image.version="${VERSION}"

# ================= BASE =================
RUN apk add --no-cache \
    ca-certificates \
    libmaxminddb \
    libmaxminddb-dev \
    tzdata \
    openssl \
    curl \
    && cp /usr/share/zoneinfo/Asia/Ho_Chi_Minh /etc/localtime \
    && echo "Asia/Ho_Chi_Minh" > /etc/timezone \
    && update-ca-certificates

# ================= NON-ROOT USER =================
# Tạo user không có quyền root để giảm attack surface nếu gateway bị compromise.
# UID/GID cố định 101 để volume permissions nhất quán giữa các lần build.
RUN addgroup -g 101 -S gateway \
    && adduser -u 101 -S -G gateway -H -D gateway

# ================= LUA ROCKS =================
RUN luarocks install lua-resty-jwt 0.2.3 \
    && luarocks install lua-resty-http 0.17.2

# ================= DIR =================
RUN mkdir -p \
    /usr/local/openresty/nginx/lua \
    /usr/local/openresty/nginx/logs \
    /usr/local/openresty/lualib/resty \
    /etc/nginx/geoip \
    /etc/letsencrypt/live/dacn3.duckdns.org

# ================= DUMMY SSL =================
# Tạo chứng chỉ giả để Nginx có thể khởi động thành công lần đầu
RUN openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
    -keyout /etc/letsencrypt/live/dacn3.duckdns.org/privkey.pem \
    -out /etc/letsencrypt/live/dacn3.duckdns.org/fullchain.pem \
    -subj "/CN=dacn3.duckdns.org"

# ================= COPY VENDOR =================
# Đưa thư mục vendor (chứa maxminddb, prometheus, v.v.) vào image
COPY vendor/resty/ /usr/local/openresty/lualib/resty/
COPY vendor/prometheus*.lua /usr/local/openresty/lualib/

# ================= GEOIP =================
COPY GeoLite2-Country.mmdb /etc/nginx/geoip/GeoLite2-Country.mmdb

# ================= CONFIG & LUA SCRIPTS =================
# Copy Nginx config và toàn bộ các file Lua 
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY lua/ /usr/local/openresty/nginx/lua/

# ================= PERMISSION =================
# Giao quyền sở hữu thư mục log và config cho user gateway (non-root)
# Nginx master process vẫn cần bind port 80/443 nên phải chạy root ở init,
# nhưng worker processes sẽ chạy dưới user 'gateway' (được cấu hình trong nginx.conf)
RUN chown -R gateway:gateway /usr/local/openresty/nginx/logs \
    && chown -R gateway:gateway /usr/local/openresty/nginx/lua \
    && chmod -R 755 /usr/local/openresty/nginx/logs \
    && chmod 644 /usr/local/openresty/nginx/conf/nginx.conf \
    && chmod -R 644 /usr/local/openresty/nginx/lua/ \
    && find /usr/local/openresty/nginx/lua/ -type d -exec chmod 755 {} \;

# ================= PORT =================
EXPOSE 80 443 9145

# ================= RUN =================
# NOTE: OpenResty master process hợp lệ phải chạy root để bind port 80/443.
# Worker processes sẽ drop xuống user 'gateway' theo cấu hình 'user gateway;' trong nginx.conf.
CMD ["openresty", "-g", "daemon off;"]