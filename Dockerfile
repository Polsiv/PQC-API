# ─── Stage 1: Build ───────────────────────────────────────────────────────────
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential cmake git pkg-config \
    libssl-dev libcurl4-openssl-dev \
    libsodium-dev libhiredis-dev \
    libpqxx-dev libpq-dev \
    nlohmann-json3-dev \
    libjsoncpp-dev uuid-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# ── Build liboqs ──────────────────────────────────────────────────────────────
# Pinned to 0.12.0 — must stay in sync with the oqs-provider tag below.
# Tracking `main` for both drifts them out of sync (algorithms get renamed).
RUN git clone --depth 1 --branch 0.12.0 \
    https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs && \
    cmake -S /tmp/liboqs -B /tmp/liboqs/build \
        -DCMAKE_BUILD_TYPE=Release \
        -DOQS_DIST_BUILD=ON \
        -DBUILD_SHARED_LIBS=ON && \
    cmake --build /tmp/liboqs/build --parallel $(nproc) && \
    cmake --install /tmp/liboqs/build

# ── Build oqs-provider ────────────────────────────────────────────────────────
# Use direct cp (same as local install) instead of cmake --install
# Pinned to 0.8.0 — the matching release for liboqs 0.12.0 (see table in
# oqs-provider RELEASE.md). 0.8.0 is the first release exposing `mldsa65`.
RUN git clone --depth 1 --branch 0.8.0 \
    https://github.com/open-quantum-safe/oqs-provider.git /tmp/oqs-provider && \
    cmake -S /tmp/oqs-provider -B /tmp/oqs-provider/build \
        -DCMAKE_BUILD_TYPE=Release \
        -DOQS_PROVIDER_BUILD_TESTING=OFF \
        -Dliboqs_DIR=/usr/local/lib/cmake/liboqs && \
    cmake --build /tmp/oqs-provider/build --parallel $(nproc) && \
    mkdir -p /usr/local/lib/ossl-modules && \
    cp /tmp/oqs-provider/build/lib/oqsprovider.so /usr/local/lib/ossl-modules/

# ── Build Drogon ──────────────────────────────────────────────────────────────
RUN git clone --depth 1 --branch v1.9.12 --recurse-submodules \
    https://github.com/drogonframework/drogon.git /tmp/drogon && \
    cmake -S /tmp/drogon -B /tmp/drogon/build \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_EXAMPLES=OFF && \
    cmake --build /tmp/drogon/build --parallel $(nproc) && \
    cmake --install /tmp/drogon/build

# ── Build the API ─────────────────────────────────────────────────────────────
COPY . /app
RUN cmake -S /app -B /app/build -DCMAKE_BUILD_TYPE=Release && \
    cmake --build /app/build --parallel $(nproc)

# ─── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM ubuntu:24.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    libssl3 libcurl4 libsodium23 \
    libhiredis-dev libpqxx-dev libpq5 \
    libjsoncpp25 \
    && rm -rf /var/lib/apt/lists/*

# Copy API binary
COPY --from=builder /app/build/pqc_api /usr/local/bin/pqc_api

# Copy frontend static files
COPY static /app/static

# Copy liboqs shared library
COPY --from=builder /usr/local/lib/liboqs.so* /usr/local/lib/

# Copy oqs-provider to where OpenSSL actually looks on Ubuntu 24.04
COPY --from=builder /usr/local/lib/ossl-modules/oqsprovider.so \
                    /usr/lib/x86_64-linux-gnu/ossl-modules/

RUN ldconfig

RUN mkdir -p /certs /logs
WORKDIR /app

EXPOSE 8443

CMD ["/usr/local/bin/pqc_api"]
