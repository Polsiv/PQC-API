# ─── Stage 1: Build ───────────────────────────────────────────────────────────
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential cmake git pkg-config \
    libssl-dev libcurl4-openssl-dev \
    libsodium-dev libhiredis-dev \
    libpqxx-dev libpq-dev \
    nlohmann-json3-dev \
    # Drogon dependencies
    libjsoncpp-dev uuid-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# ── Build liboqs ──────────────────────────────────────────────────────────────
RUN git clone --depth 1 --branch main \
    https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs && \
    cmake -S /tmp/liboqs -B /tmp/liboqs/build \
        -DCMAKE_BUILD_TYPE=Release \
        -DOQS_DIST_BUILD=ON \
        -DBUILD_SHARED_LIBS=ON && \
    cmake --build /tmp/liboqs/build --parallel $(nproc) && \
    cmake --install /tmp/liboqs/build

# ── Build oqs-provider ────────────────────────────────────────────────────────
RUN git clone --depth 1 \
    https://github.com/open-quantum-safe/oqs-provider.git /tmp/oqs-provider && \
    cmake -S /tmp/oqs-provider -B /tmp/oqs-provider/build \
        -DCMAKE_BUILD_TYPE=Release \
        -Dliboqs_DIR=/usr/local/lib/cmake/liboqs && \
    cmake --build /tmp/oqs-provider/build --parallel $(nproc) && \
    mkdir -p /usr/local/lib/ossl-modules && \
    cp /tmp/oqs-provider/build/lib/oqsprovider.so /usr/local/lib/ossl-modules/

# ── Build Drogon ──────────────────────────────────────────────────────────────
RUN git clone --depth 1 --recurse-submodules \
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
    && rm -rf /var/lib/apt/lists/*

# Copy built binaries and shared libs from builder
COPY --from=builder /app/build/pqc_api        /usr/local/bin/pqc_api
COPY --from=builder /usr/local/lib/liboqs.so* /usr/local/lib/
COPY --from=builder /usr/local/lib/ossl-modules/oqsprovider.so \
                    /usr/local/lib/ossl-modules/

# Configure OpenSSL to find the OQS provider
RUN echo "\n[provider_sect]\noqsprovider = oqs_provider\n\
[oqs_provider]\nactivate = 1" >> /etc/ssl/openssl.cnf

RUN ldconfig

# Runtime directories
RUN mkdir -p /certs /logs
WORKDIR /app

EXPOSE 8443

CMD ["/usr/local/bin/pqc_api"]
