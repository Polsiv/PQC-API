# Builds and runs the PQC key-exchange microbenchmark against the SAME liboqs
# the API server uses (main branch, OQS_DIST_BUILD=ON, Release → runtime AVX2
# detection), plus the system OpenSSL for X25519. The liboqs build layer is
# cached, so only kem_bench.cpp recompiles on subsequent builds.
#
# Build & run:
#   docker build -t pqc-kem-bench -f bench/Dockerfile bench
#   docker run --rm pqc-kem-bench -n 100000 -rounds 12
#
# Write a CSV out to the host (mount a directory):
#   docker run --rm -v "$PWD/bench:/out" pqc-kem-bench -csv /out/kem_bench.csv

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential cmake git pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# liboqs — identical flags to the server build (see ../Dockerfile).
RUN git clone --depth 1 --branch main \
    https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs && \
    cmake -S /tmp/liboqs -B /tmp/liboqs/build \
        -DCMAKE_BUILD_TYPE=Release \
        -DOQS_DIST_BUILD=ON \
        -DBUILD_SHARED_LIBS=ON && \
    cmake --build /tmp/liboqs/build --parallel $(nproc) && \
    cmake --install /tmp/liboqs/build && \
    ldconfig

COPY kem_bench.cpp /bench/kem_bench.cpp
RUN g++ -O3 -DNDEBUG -std=c++17 /bench/kem_bench.cpp -o /bench/kem_bench \
    -I/usr/local/include -L/usr/local/lib -loqs -lcrypto

ENTRYPOINT ["/bench/kem_bench"]
