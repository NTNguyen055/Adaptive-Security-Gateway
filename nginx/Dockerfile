FROM openresty/openresty:alpine-fat

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

# ================= LUA ROCKS =================
# Chỉ cài 2 thư viện này qua Luarocks giống hệt file cũ của bạn đã chạy thành công
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
# Bê nguyên xi thư mục vendor (chứa maxminddb, prometheus, v.v.) vào image
COPY vendor/resty/ /usr/local/openresty/lualib/resty/
COPY vendor/prometheus*.lua /usr/local/openresty/lualib/

# ================= GEOIP =================
COPY GeoLite2-Country.mmdb /etc/nginx/geoip/GeoLite2-Country.mmdb

# ================= CONFIG & LUA SCRIPTS =================
# Copy Nginx config và toàn bộ các file Lua siêu bảo mật mà chúng ta vừa nâng cấp
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY lua/ /usr/local/openresty/nginx/lua/

# ================= PERMISSION =================
RUN chmod -R 755 /usr/local/openresty/

# ================= PORT =================
EXPOSE 80 443 9145

# ================= RUN =================
CMD ["openresty", "-g", "daemon off;"]