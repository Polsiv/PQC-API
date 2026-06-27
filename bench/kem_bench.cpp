// PQC key-exchange primitive microbenchmark (server-representative).
//
// Measures the raw CPU cost of the key-exchange primitives used by the TLS 1.3
// handshake, using the SAME crypto stack as the API server:
//   • ML-KEM-768 via liboqs' OQS_KEM API (the code oqs-provider wraps in TLS)
//   • X25519     via OpenSSL EVP (OpenSSL's classical ECDHE)
//
// It runs isolated from the server on purpose: the live server's per-handshake
// CPU is dominated by background threads and the certificate signature, which
// swamps the (small) ML-KEM-vs-X25519 difference. Isolating the primitive is
// the only way to resolve that difference cleanly. Build it against the same
// liboqs the server uses (see bench/Dockerfile) so the absolute numbers are
// representative of your system.
//
// X25519MLKEM768 is a HYBRID — it runs X25519 AND ML-KEM-768 together — so the
// marginal cost of going post-quantum is the ML-KEM work added on top of the
// X25519 both configs already do:
//   server (encapsulator) adds:  ML-KEM-768 Encapsulate
//   client (decapsulator) adds:  ML-KEM-768 KeyGen + Decapsulate

#include <oqs/oqs.h>
#include <openssl/evp.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

using clock_type = std::chrono::steady_clock;

// Defeats dead-code elimination: every benchmarked op folds a byte of its
// output into this volatile sink so the compiler cannot optimise it away.
volatile uint64_t g_sink = 0;

struct Res {
    std::string name;
    double ns_best = 0;  // minimum round → cleanest estimate of pure compute
    double ns_mean = 0;
    double ops = 0;
};

// bench warms up, then runs `rounds` timed batches of `iters` calls and reports
// both the best (minimum) and mean per-op time. The minimum is the round least
// disturbed by GC/scheduler, so it best reflects pure compute cost.
template <class F>
Res bench(const std::string& name, long iters, int rounds, F fn) {
    for (long i = 0; i < iters / 10 + 1; ++i) fn();  // warmup
    double best = 1e30, sum = 0;
    for (int r = 0; r < rounds; ++r) {
        auto t0 = clock_type::now();
        for (long i = 0; i < iters; ++i) fn();
        auto t1 = clock_type::now();
        double el =
            std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
        best = std::min(best, el);
        sum += el;
    }
    double nb = best / iters;
    double nm = (sum / rounds) / iters;
    return {name, nb, nm, 1e9 / nb};
}

static EVP_PKEY* gen_x25519() {
    EVP_PKEY_CTX* c = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    EVP_PKEY_keygen_init(c);
    EVP_PKEY* k = nullptr;
    EVP_PKEY_keygen(c, &k);
    EVP_PKEY_CTX_free(c);
    return k;
}

int main(int argc, char** argv) {
    long iters = 50000;
    int rounds = 10;
    std::string csv;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-n" && i + 1 < argc)
            iters = std::atol(argv[++i]);
        else if (a == "-rounds" && i + 1 < argc)
            rounds = std::atoi(argv[++i]);
        else if (a == "-csv" && i + 1 < argc)
            csv = argv[++i];
    }

    std::printf("═══════════════════════════════════════════════════════════════\n");
    std::printf("  PQC Key-Exchange Primitive Microbenchmark (liboqs + OpenSSL)\n");
    std::printf("  liboqs version    : %s\n", OQS_version());
    std::printf("  Iterations/round  : %ld\n", iters);
    std::printf("  Rounds            : %d (reporting the minimum)\n", rounds);
    std::printf("═══════════════════════════════════════════════════════════════\n");

    // ── ML-KEM-768 (liboqs) ────────────────────────────────────────────────
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) {
        std::fprintf(stderr,
                     "OQS_KEM_new(ml_kem_768) returned NULL — is ML-KEM enabled "
                     "in this liboqs build?\n");
        return 1;
    }
    std::vector<uint8_t> pk(kem->length_public_key);
    std::vector<uint8_t> sk(kem->length_secret_key);
    std::vector<uint8_t> ct(kem->length_ciphertext);
    std::vector<uint8_t> ss(kem->length_shared_secret);
    // Seed one keypair + ciphertext for the encaps/decaps benchmarks.
    OQS_KEM_keypair(kem, pk.data(), sk.data());
    OQS_KEM_encaps(kem, ct.data(), ss.data(), pk.data());

    // ── X25519 (OpenSSL) ───────────────────────────────────────────────────
    EVP_PKEY* x_priv = gen_x25519();
    EVP_PKEY* x_peer = gen_x25519();

    // Persistent derive context: init + set peer once, then time EVP_PKEY_derive.
    EVP_PKEY_CTX* dctx = EVP_PKEY_CTX_new(x_priv, nullptr);
    EVP_PKEY_derive_init(dctx);
    EVP_PKEY_derive_set_peer(dctx, x_peer);
    size_t secret_len = 32;
    std::vector<uint8_t> secret(secret_len);

    // Persistent keygen context for the X25519 keygen benchmark.
    EVP_PKEY_CTX* kgctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    EVP_PKEY_keygen_init(kgctx);

    std::vector<Res> results;
    results.push_back(bench("X25519 KeyGen", iters, rounds, [&] {
        EVP_PKEY* k = nullptr;
        EVP_PKEY_keygen(kgctx, &k);
        g_sink ^= reinterpret_cast<uintptr_t>(k);
        EVP_PKEY_free(k);
    }));
    results.push_back(bench("X25519 Derive (ECDH)", iters, rounds, [&] {
        size_t len = secret_len;
        EVP_PKEY_derive(dctx, secret.data(), &len);
        g_sink ^= secret[0];
    }));
    results.push_back(bench("ML-KEM-768 KeyGen", iters, rounds, [&] {
        OQS_KEM_keypair(kem, pk.data(), sk.data());
        g_sink ^= pk[0];
    }));
    results.push_back(bench("ML-KEM-768 Encapsulate", iters, rounds, [&] {
        OQS_KEM_encaps(kem, ct.data(), ss.data(), pk.data());
        g_sink ^= ct[0] ^ ss[0];
    }));
    results.push_back(bench("ML-KEM-768 Decapsulate", iters, rounds, [&] {
        OQS_KEM_decaps(kem, ss.data(), ct.data(), sk.data());
        g_sink ^= ss[0];
    }));

    // ── Per-operation table ──────────────────────────────────────────────
    std::printf("\n  Per-operation cost (single-threaded):\n");
    std::printf("  %-26s  %12s  %12s  %14s\n", "operation", "best us/op",
                "mean us/op", "ops/sec");
    for (const auto& r : results)
        std::printf("  %-26s  %12.3f  %12.3f  %14.0f\n", r.name.c_str(),
                    r.ns_best / 1000, r.ns_mean / 1000, r.ops);

    auto by = [&](const std::string& n) {
        for (const auto& r : results)
            if (r.name == n) return r.ns_best;
        return 0.0;
    };
    double xKg = by("X25519 KeyGen");
    double xDer = by("X25519 Derive (ECDH)");
    double mKg = by("ML-KEM-768 KeyGen");
    double mEnc = by("ML-KEM-768 Encapsulate");
    double mDec = by("ML-KEM-768 Decapsulate");

    double classical = xKg + xDer;                 // per side
    double hybridServer = xKg + xDer + mEnc;        // encapsulator
    double hybridClient = xKg + xDer + mKg + mDec;  // decapsulator

    std::printf("\n  Key-exchange cost per handshake side (derived, best-case):\n");
    std::printf("  %-44s  %10.3f us\n", "Classical X25519 (per side)",
                classical / 1000);
    std::printf("  %-44s  %10.3f us\n", "Hybrid server side (X25519 + ML-KEM enc)",
                hybridServer / 1000);
    std::printf("  %-44s  %10.3f us\n",
                "Hybrid client side (X25519 + ML-KEM kg+dec)", hybridClient / 1000);
    std::printf("  ─────────────────────────────────────────────────────────────\n");
    std::printf("  %-44s  %10.3f us  (%.2fx)\n", "→ PQC adds, server side",
                mEnc / 1000, hybridServer / classical);
    std::printf("  %-44s  %10.3f us  (%.2fx)\n", "→ PQC adds, client side",
                (mKg + mDec) / 1000, hybridClient / classical);
    std::printf("═══════════════════════════════════════════════════════════════\n");

    if (!csv.empty()) {
        std::ofstream f(csv);
        if (f) {
            f << "operation,ns_per_op_best,ns_per_op_mean,ops_per_sec\n";
            for (const auto& r : results)
                f << r.name << ',' << r.ns_best << ',' << r.ns_mean << ','
                  << r.ops << '\n';
            std::printf("\n  CSV exported → %s\n", csv.c_str());
        }
    }

    // Cleanup.
    EVP_PKEY_CTX_free(kgctx);
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(x_priv);
    EVP_PKEY_free(x_peer);
    OQS_KEM_free(kem);
    return 0;
}
