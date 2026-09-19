# Sử dụng Python 3.11 Debian Bookworm Slim
FROM python:3.11-slim-bookworm

# Thiết lập các biến môi trường
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    PYTHONUTF8=1 \
    ALLOW_PUBLIC_BIND=1 \
    DOCKER=1 \
    PORT=5033 \
    XDG_CACHE_HOME=/app/runtime/camoufox-cache \
    XDG_DATA_HOME=/app/runtime

# Cài đặt các gói hệ thống Linux, Node.js (cho Sentinel QuickJS) và thư viện đồ họa cho headless browser
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget \
    git \
    nodejs \
    xvfb \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcairo2 \
    libcups2 \
    libdbus-1-3 \
    libdrm2 \
    libgbm1 \
    libglib2.0-0 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libpango-1.0-0 \
    libx11-6 \
    libx11-xcb1 \
    libxcb1 \
    libxcomposite1 \
    libxcursor1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxi6 \
    libxrandr2 \
    libxrender1 \
    libxss1 \
    libxtst6 \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

# Thiết lập thư mục làm việc
WORKDIR /app

# Cài đặt thư viện Python trước để tận dụng Docker layer cache
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Cài đặt browser Playwright và Camoufox theo spec ghim
COPY camoufox-browser-spec.txt .
RUN playwright install chromium && \
    playwright install-deps && \
    SPEC=$(cat camoufox-browser-spec.txt | tr -d '\r\n') && \
    python -m camoufox fetch "$SPEC"

# Copy toàn bộ mã nguồn vào container
COPY . .

# Tạo thư mục runtime để lưu database và cache
RUN mkdir -p /app/runtime/camoufox-cache /app/runtime/Lehaipreshop/Change2FA

# Mở cổng mặc định
EXPOSE 5033

# Khởi động ứng dụng (tự động nhận biến $PORT từ Render)
CMD ["sh", "-c", "python server.py --host 0.0.0.0 --port ${PORT:-5033} --no-browser"]
