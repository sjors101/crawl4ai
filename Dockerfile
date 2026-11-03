# Debian 13 "trixie": bookworm is on LTS and many CVEs (util-linux, Xorg, ...)
# are only fixed in trixie.
FROM python:3.12-slim-trixie AS build

# C4ai version
ARG C4AI_VER=0.9.5
ENV C4AI_VERSION=$C4AI_VER
LABEL c4ai.version=$C4AI_VER

# Set build arguments
ARG APP_HOME=/app
ARG GITHUB_REPO=https://github.com/unclecode/crawl4ai.git
ARG GITHUB_BRANCH=main
ARG USE_LOCAL=true

ENV PYTHONFAULTHANDLER=1 \
    PYTHONHASHSEED=random \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_DEFAULT_TIMEOUT=100 \
    DEBIAN_FRONTEND=noninteractive \
    REDIS_HOST=localhost \
    REDIS_PORT=6379

ARG PYTHON_VERSION=3.12
ARG INSTALL_TYPE=default
ARG ENABLE_GPU=false
ARG TARGETARCH

# Redis version — pinned to a CVE-patched release on the BSD-licensed 7.2 line.
# 7.2.7 (the previous pin) is affected by CVE-2025-49844 ("RediShell", Lua
# use-after-free RCE), CVE-2025-46817/46818/46819, CVE-2025-32023,
# CVE-2025-48367 and CVE-2025-21605; 7.2.11+ fixes them.
# Override with --build-arg REDIS_VERSION="" for latest, or
# --build-arg REDIS_VERSION="6:7.2.17-1rl1~trixie1" for a specific version.
ARG REDIS_VERSION="6:7.2.17-1rl1~trixie1"
# Fingerprint of the Redis package signing key ("Redis (Package Signing)
# <redis-packages@redis.io>"). The build fails if packages.redis.io serves a
# different key, so a tampered key download cannot authorize packages.
ARG REDIS_GPG_FINGERPRINT=54318FA4052D1E61A6B6F7BB5F4349D6BF53AA0C

LABEL maintainer="unclecode"
LABEL description="🔥🕷️ Crawl4AI: Open-source LLM Friendly Web Crawler & scraper"
LABEL version="1.0"

# Install curl and gnupg first (needed to add Redis repo)
RUN apt-get update && apt-get install -y --no-install-recommends curl gnupg \
    && rm -rf /var/lib/apt/lists/*

# Add official Redis repository for security-patched versions. The signing key
# is verified against the pinned fingerprint before apt is allowed to trust it.
RUN curl -fsSL --proto '=https' --tlsv1.2 https://packages.redis.io/gpg -o /tmp/redis.asc \
    && actual="$(gpg --show-keys --with-colons /tmp/redis.asc | awk -F: '/^fpr:/{print $10; exit}')" \
    && if [ "$actual" != "$REDIS_GPG_FINGERPRINT" ]; then \
         echo "Redis signing key fingerprint mismatch: got '$actual', want '$REDIS_GPG_FINGERPRINT'" >&2; exit 1; \
       fi \
    && gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg /tmp/redis.asc \
    && rm -f /tmp/redis.asc \
    && echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb trixie main" \
    > /etc/apt/sources.list.d/redis.list

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    wget \
    gnupg \
    git \
    cmake \
    pkg-config \
    python3-dev \
    libjpeg-dev \
    redis-tools${REDIS_VERSION:+=$REDIS_VERSION} \
    redis-server${REDIS_VERSION:+=$REDIS_VERSION} \
    && if [ -n "$REDIS_VERSION" ]; then apt-mark hold redis-server redis-tools; fi \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y --no-install-recommends \
    libglib2.0-0t64 \
    libnss3 \
    libnspr4 \
    libatk1.0-0t64 \
    libatk-bridge2.0-0t64 \
    libcups2t64 \
    libdrm2 \
    libdbus-1-3 \
    libxcb1 \
    libxkbcommon0 \
    libx11-6 \
    libxcomposite1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libpango-1.0-0 \
    libcairo2 \
    libasound2t64 \
    libatspi2.0-0t64 \
    && apt-get clean \ 
    && rm -rf /var/lib/apt/lists/*

# Held packages (the pinned Redis) are not touched; without the hold above this
# step silently replaced the pinned Redis with the repo's newest major.
RUN apt-get update && apt-get dist-upgrade -y \
    && rm -rf /var/lib/apt/lists/*

RUN if [ "$ENABLE_GPU" = "true" ] && [ "$TARGETARCH" = "amd64" ] ; then \
    echo "deb http://deb.debian.org/debian trixie contrib non-free" >> /etc/apt/sources.list \
    && apt-get update && apt-get install -y --no-install-recommends \
    nvidia-cuda-toolkit \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* ; \
else \
    echo "Skipping NVIDIA CUDA Toolkit installation (unsupported platform or GPU disabled)"; \
fi

RUN if [ "$TARGETARCH" = "arm64" ]; then \
    echo "🦾 Installing ARM-specific optimizations"; \
    apt-get update && apt-get install -y --no-install-recommends \
    libopenblas-dev \
    && apt-get clean \ 
    && rm -rf /var/lib/apt/lists/*; \
elif [ "$TARGETARCH" = "amd64" ]; then \
    echo "🖥️ Installing AMD64-specific optimizations"; \
    apt-get update && apt-get install -y --no-install-recommends \
    libomp-dev \
    && apt-get clean \ 
    && rm -rf /var/lib/apt/lists/*; \
else \
    echo "Skipping platform-specific optimizations (unsupported platform)"; \
fi

# Create a non-root user and group
RUN groupadd -r appuser && useradd --no-log-init -r -g appuser appuser

# Create and set permissions for appuser home directory
RUN mkdir -p /home/appuser && chown -R appuser:appuser /home/appuser

WORKDIR ${APP_HOME}

RUN echo '#!/bin/bash\n\
if [ "$USE_LOCAL" = "true" ]; then\n\
    echo "📦 Installing from local source..."\n\
    pip install --no-cache-dir /tmp/project/\n\
else\n\
    echo "🌐 Installing from GitHub..."\n\
    for i in {1..3}; do \n\
        git clone --branch ${GITHUB_BRANCH} ${GITHUB_REPO} /tmp/crawl4ai && break || \n\
        { echo "Attempt $i/3 failed! Taking a short break... ☕"; sleep 5; }; \n\
    done\n\
    pip install --no-cache-dir /tmp/crawl4ai\n\
fi' > /tmp/install.sh && chmod +x /tmp/install.sh

COPY . /tmp/project/

# Copy supervisor config first (might need root later, but okay for now)
COPY deploy/docker/supervisord.conf .

COPY deploy/docker/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN if [ "$INSTALL_TYPE" = "all" ] ; then \
        pip install --no-cache-dir \
            torch \
            torchvision \
            torchaudio \
            scikit-learn \
            nltk \
            transformers \
            tokenizers && \
        python -m nltk.downloader punkt stopwords ; \
    fi

RUN if [ "$INSTALL_TYPE" = "all" ] ; then \
        pip install "/tmp/project/[all]" && \
        python -m crawl4ai.model_loader ; \
    elif [ "$INSTALL_TYPE" = "torch" ] ; then \
        pip install "/tmp/project/[torch]" ; \
    elif [ "$INSTALL_TYPE" = "transformer" ] ; then \
        pip install "/tmp/project/[transformer]" && \
        python -m crawl4ai.model_loader ; \
    else \
        pip install "/tmp/project" ; \
    fi

RUN pip install --no-cache-dir --upgrade pip && \
    /tmp/install.sh && \
    python -c "import crawl4ai; print('✅ crawl4ai is ready to rock!')" && \
    python -c "from playwright.sync_api import sync_playwright; print('✅ Playwright is feeling dramatic!')"

RUN crawl4ai-setup

# Only Chromium is used (and only Chromium is copied to appuser below); the
# Firefox/WebKit builds were unreachable dead weight that still had to be patched.
RUN playwright install --with-deps chromium

RUN mkdir -p /home/appuser/.cache/ms-playwright \
    && cp -r /root/.cache/ms-playwright/chromium-* \
        /root/.cache/ms-playwright/chromium_headless_shell-* \
        /home/appuser/.cache/ms-playwright/ \
    && chown -R appuser:appuser /home/appuser/.cache/ms-playwright

RUN crawl4ai-doctor

# Remove the build-time source copy and installer (they are not needed at
# runtime) and the compiler toolchain / VCS / downloaders used only to build:
# a foothold in the container should not come with gcc, git and wget.
# Xvfb/X server: pulled in by `playwright install --with-deps` for headed mode,
# which nothing here starts (no DISPLAY). curl: only used to fetch the Redis key
# at build time; the healthchecks use Python instead.
# (root's Playwright cache is only needed by crawl4ai-doctor above; appuser
# has its own copy.)
RUN rm -rf /tmp/project /tmp/crawl4ai /tmp/install.sh /root/.cache/ms-playwright \
    && apt-mark manual $(dpkg-query -W -f '${db:Status-Abbrev} ${Package}\n' \
         'libjpeg62-turbo' 'libopenblas0*' 'libomp5*' 2>/dev/null | awk '$1 == "ii" {print $2}') \
    && apt-get purge -y --auto-remove \
        build-essential cmake pkg-config python3-dev git wget gnupg \
        libjpeg-dev libopenblas-dev libomp-dev libc6-dev linux-libc-dev \
        xvfb xserver-common xauth curl \
    && rm -rf /var/lib/apt/lists/* /root/.cache/pip \
    && python -c "import crawl4ai, playwright, redis, gunicorn, supervisor; print('✅ runtime imports OK after toolchain purge')"

# Ensure all cache directories belong to appuser
# This fixes permission issues with .cache/url_seeder and other runtime cache dirs
RUN mkdir -p /home/appuser/.cache \
    && chown -R appuser:appuser /home/appuser/.cache

# Copy application code
COPY deploy/docker/* ${APP_HOME}/

# copy the playground + any future static assets
COPY deploy/docker/static ${APP_HOME}/static

# /app is root-owned and read-only to the runtime user: a write bug can no
# longer plant a persistent self-RCE in the application directory.
RUN chown -R root:root ${APP_HOME} && chmod -R a-w ${APP_HOME}

# give permissions to redis persistence dirs if used
RUN mkdir -p /var/lib/redis /var/log/redis && chown -R appuser:appuser /var/lib/redis /var/log/redis

# Sandboxed artifact store (server-owned screenshot/PDF outputs), 0700.
RUN mkdir -p /var/lib/crawl4ai/outputs \
    && chown -R appuser:appuser /var/lib/crawl4ai \
    && chmod 700 /var/lib/crawl4ai/outputs

# Python, not curl (curl is purged above). /health covers the app; redis
# requires a password, so an unauthenticated `redis-cli ping` proved nothing.
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import os,sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ.get('CRAWL4AI_PORT','11235'), timeout=5).status == 200 else 1)"]

# Redis is in-container only (loopback + requirepass); never expose its port.
# (was: EXPOSE 6379)
# Switch to the non-root user before starting the application
USER appuser

# Set environment variables to ptoduction
ENV PYTHON_ENV=production 

# Start via entrypoint.sh, which resolves the socket-level auth/egress posture
# (loopback unless a credential is present) and the redis password, then execs
# supervisord.
CMD ["bash", "entrypoint.sh"]
