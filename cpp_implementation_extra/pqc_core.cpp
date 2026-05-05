/**
 * pqc_core.cpp
 * ============
 * Extra Credit: C++ implementation of the quantum-resistant hybrid encryption core.
 *
 * This file implements the same protocol as base_protocol.py but in C++, using:
 *   - liboqs (Open Quantum Safe) for Kyber768 / McEliece KEM
 *   - OpenSSL 3.x EVP API for AES-256-GCM encryption
 *   - OpenSSL HKDF (HKDF-SHA256) for key derivation
 *
 * Build (macOS with Homebrew liboqs + OpenSSL 3):
 *   brew install liboqs openssl@3
 *   g++ -std=c++17 -O2 \
 *       -I$(brew --prefix liboqs)/include \
 *       -I$(brew --prefix openssl@3)/include \
 *       -L$(brew --prefix liboqs)/lib \
 *       -L$(brew --prefix openssl@3)/lib \
 *       pqc_core.cpp -o pqc_core \
 *       -loqs -lcrypto -lssl
 *
 * Build (Ubuntu/Debian with liboqs installed):
 *   sudo apt install liboqs-dev libssl-dev
 *   g++ -std=c++17 -O2 pqc_core.cpp -o pqc_core -loqs -lcrypto -lssl
 *
 * Usage:
 *   ./pqc_core kyber    "Hello, quantum world!"
 *   ./pqc_core mceliece "Hello, quantum world!"
 */

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cassert>
#include <chrono>

// liboqs C header (C++ compatible with extern "C" guard inside)
#include <oqs/oqs.h>

// OpenSSL EVP for AES-256-GCM + HKDF
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/err.h>

/* ─────────────────────────────────────────────────────────────────────────
   Constants
   ───────────────────────────────────────────────────────────────────────── */
static constexpr size_t AES_KEY_LEN   = 32;   // 256 bits
static constexpr size_t GCM_NONCE_LEN = 12;   // 96 bits (GCM standard)
static constexpr size_t GCM_TAG_LEN   = 16;   // 128 bits

static const uint8_t HKDF_SALT[]  = {'q','u','a','n','t','u','m','-','r','e','s','i','s','t','a','n','t','-','a','e','s'};
static const uint8_t HKDF_INFO[]  = {'s','e','c','u','r','e','-','c','h','a','n','n','e','l','-','v','1'};

/* ─────────────────────────────────────────────────────────────────────────
   Utility helpers
   ───────────────────────────────────────────────────────────────────────── */
static void ossl_check(int rc, const char* where) {
    if (rc != 1) {
        std::cerr << "[OpenSSL error at " << where << "]\n";
        ERR_print_errors_fp(stderr);
        std::exit(1);
    }
}

static std::string hexdump(const uint8_t* data, size_t len, size_t max_bytes = 32) {
    std::ostringstream oss;
    size_t show = std::min(len, max_bytes);
    for (size_t i = 0; i < show; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(data[i]);
        if (i % 16 == 15) oss << "\n    ";
        else oss << ' ';
    }
    if (len > max_bytes) oss << "... (" << std::dec << len << " bytes total)";
    return oss.str();
}

static double ms_since(std::chrono::time_point<std::chrono::high_resolution_clock> t0) {
    auto now = std::chrono::high_resolution_clock::now();
    return std::chrono::duration<double, std::milli>(now - t0).count();
}

/* ─────────────────────────────────────────────────────────────────────────
   SecureChannel: AES-256-GCM with HKDF key derivation
   Mirrors src/secure_channel.py exactly.
   ───────────────────────────────────────────────────────────────────────── */
struct EncryptedPayload {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> tag;          // 16 bytes GCM tag
    std::vector<uint8_t> nonce;        // 12 bytes
};

class SecureChannel {
public:
    explicit SecureChannel(const uint8_t* shared_secret, size_t secret_len) {
        derive_key(shared_secret, secret_len);
    }

    EncryptedPayload encrypt(const std::string& plaintext) {
        EncryptedPayload out;
        out.nonce.resize(GCM_NONCE_LEN);
        out.tag.resize(GCM_TAG_LEN);

        // Random nonce
        ossl_check(RAND_bytes(out.nonce.data(), GCM_NONCE_LEN), "RAND_bytes nonce");

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) { std::cerr << "EVP_CIPHER_CTX_new failed\n"; std::exit(1); }

        ossl_check(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr),
                   "EncryptInit (alg)");
        ossl_check(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_LEN, nullptr),
                   "set iv len");
        ossl_check(EVP_EncryptInit_ex(ctx, nullptr, nullptr, key_.data(), out.nonce.data()),
                   "EncryptInit (key+iv)");

        const uint8_t* pt = reinterpret_cast<const uint8_t*>(plaintext.data());
        out.ciphertext.resize(plaintext.size());
        int outl = 0;
        ossl_check(EVP_EncryptUpdate(ctx, out.ciphertext.data(), &outl, pt, (int)plaintext.size()),
                   "EncryptUpdate");
        int final_len = 0;
        ossl_check(EVP_EncryptFinal_ex(ctx, out.ciphertext.data() + outl, &final_len),
                   "EncryptFinal");
        out.ciphertext.resize(outl + final_len);

        ossl_check(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, out.tag.data()),
                   "get GCM tag");

        EVP_CIPHER_CTX_free(ctx);
        return out;
    }

    std::string decrypt(const EncryptedPayload& payload) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) { std::cerr << "EVP_CIPHER_CTX_new failed\n"; std::exit(1); }

        ossl_check(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr),
                   "DecryptInit (alg)");
        ossl_check(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_LEN, nullptr),
                   "set iv len");
        ossl_check(EVP_DecryptInit_ex(ctx, nullptr, nullptr, key_.data(), payload.nonce.data()),
                   "DecryptInit (key+iv)");

        std::vector<uint8_t> plaintext(payload.ciphertext.size());
        int outl = 0;
        ossl_check(EVP_DecryptUpdate(ctx, plaintext.data(), &outl,
                                     payload.ciphertext.data(), (int)payload.ciphertext.size()),
                   "DecryptUpdate");

        // Set expected tag before calling Final
        ossl_check(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN,
                                       const_cast<uint8_t*>(payload.tag.data())),
                   "set GCM tag");

        int final_len = 0;
        int rc = EVP_DecryptFinal_ex(ctx, plaintext.data() + outl, &final_len);
        EVP_CIPHER_CTX_free(ctx);

        if (rc != 1) {
            return "[DECRYPTION FAILED: GCM authentication tag mismatch — possible tampering]";
        }
        plaintext.resize(outl + final_len);
        return std::string(plaintext.begin(), plaintext.end());
    }

private:
    std::vector<uint8_t> key_;  // AES-256 key (32 bytes)

    void derive_key(const uint8_t* secret, size_t secret_len) {
        key_.resize(AES_KEY_LEN);

        EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
        if (!kdf) { std::cerr << "EVP_KDF_fetch HKDF failed\n"; std::exit(1); }

        EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
        EVP_KDF_free(kdf);
        if (!kctx) { std::cerr << "EVP_KDF_CTX_new failed\n"; std::exit(1); }

        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>("SHA256"), 0),
            OSSL_PARAM_construct_octet_string("key",
                const_cast<uint8_t*>(secret), secret_len),
            OSSL_PARAM_construct_octet_string("salt",
                const_cast<uint8_t*>(HKDF_SALT), sizeof(HKDF_SALT)),
            OSSL_PARAM_construct_octet_string("info",
                const_cast<uint8_t*>(HKDF_INFO), sizeof(HKDF_INFO)),
            OSSL_PARAM_END
        };

        if (EVP_KDF_derive(kctx, key_.data(), AES_KEY_LEN, params) != 1) {
            std::cerr << "HKDF derive failed\n";
            ERR_print_errors_fp(stderr);
            std::exit(1);
        }
        EVP_KDF_CTX_free(kctx);
    }
};

/* ─────────────────────────────────────────────────────────────────────────
   run_scheme(): perform full KEM + AES-256-GCM round-trip for one scheme
   ───────────────────────────────────────────────────────────────────────── */
static void run_scheme(const char* kem_name, const std::string& message) {
    std::cout << "\n";
    std::cout << "══════════════════════════════════════════════════════════════\n";
    std::cout << "  Scheme: " << kem_name << "\n";
    std::cout << "══════════════════════════════════════════════════════════════\n\n";

    OQS_KEM* kem = OQS_KEM_new(kem_name);
    if (!kem) {
        std::cerr << "[ERROR] OQS_KEM_new(\"" << kem_name << "\") failed.\n"
                  << "        Make sure liboqs is compiled with this algorithm enabled.\n";
        return;
    }

    std::cout << "  Public key length:   " << kem->length_public_key  << " bytes\n";
    std::cout << "  Secret key length:   " << kem->length_secret_key  << " bytes\n";
    std::cout << "  Ciphertext length:   " << kem->length_ciphertext  << " bytes\n";
    std::cout << "  Shared secret len:   " << kem->length_shared_secret << " bytes\n\n";

    std::vector<uint8_t> pk(kem->length_public_key);
    std::vector<uint8_t> sk(kem->length_secret_key);
    std::vector<uint8_t> ct(kem->length_ciphertext);
    std::vector<uint8_t> ss_alice(kem->length_shared_secret);
    std::vector<uint8_t> ss_bob  (kem->length_shared_secret);

    // ── Step 1: Key generation (Bob) ──────────────────────────────────
    auto t0 = std::chrono::high_resolution_clock::now();
    OQS_STATUS rc = OQS_KEM_keypair(kem, pk.data(), sk.data());
    double keygen_ms = ms_since(t0);
    if (rc != OQS_SUCCESS) { std::cerr << "  keypair() failed\n"; OQS_KEM_free(kem); return; }
    std::cout << "[1] Bob generated keypair          " << std::fixed << std::setprecision(3)
              << keygen_ms << " ms\n";
    std::cout << "    Public key (first 32 B): " << hexdump(pk.data(), pk.size(), 32) << "\n\n";

    // ── Step 2: Encapsulation (Alice) ─────────────────────────────────
    t0 = std::chrono::high_resolution_clock::now();
    rc = OQS_KEM_encaps(kem, ct.data(), ss_alice.data(), pk.data());
    double encap_ms = ms_since(t0);
    if (rc != OQS_SUCCESS) { std::cerr << "  encaps() failed\n"; OQS_KEM_free(kem); return; }
    std::cout << "[2] Alice encapsulated secret      " << encap_ms << " ms\n";
    std::cout << "    KEM ciphertext (first 32 B): "
              << hexdump(ct.data(), ct.size(), 32) << "\n";
    std::cout << "    Shared secret: " << hexdump(ss_alice.data(), ss_alice.size(), 32) << "\n\n";

    // ── Step 3: AES-256-GCM Encryption (Alice) ────────────────────────
    SecureChannel alice_ch(ss_alice.data(), ss_alice.size());
    t0 = std::chrono::high_resolution_clock::now();
    EncryptedPayload payload = alice_ch.encrypt(message);
    double enc_ms = ms_since(t0);
    std::cout << "[3] Alice encrypted message        " << enc_ms << " ms\n";
    std::cout << "    Plaintext length:  " << message.size() << " bytes\n";
    std::cout << "    Ciphertext length: " << payload.ciphertext.size() << " bytes\n";
    std::cout << "    Nonce:   " << hexdump(payload.nonce.data(), GCM_NONCE_LEN, GCM_NONCE_LEN) << "\n";
    std::cout << "    Auth Tag:" << hexdump(payload.tag.data(), GCM_TAG_LEN, GCM_TAG_LEN) << "\n";
    std::cout << "    CT:      " << hexdump(payload.ciphertext.data(), payload.ciphertext.size()) << "\n\n";

    // ── Step 4: Decapsulation (Bob) ───────────────────────────────────
    t0 = std::chrono::high_resolution_clock::now();
    rc = OQS_KEM_decaps(kem, ss_bob.data(), ct.data(), sk.data());
    double decap_ms = ms_since(t0);
    if (rc != OQS_SUCCESS) { std::cerr << "  decaps() failed\n"; OQS_KEM_free(kem); return; }
    std::cout << "[4] Bob decapsulated secret        " << decap_ms << " ms\n";
    bool secrets_match = (ss_alice == ss_bob);
    std::cout << "    Shared secrets match: " << (secrets_match ? "YES ✓" : "NO ✗") << "\n\n";

    // ── Step 5: AES-256-GCM Decryption (Bob) ─────────────────────────
    SecureChannel bob_ch(ss_bob.data(), ss_bob.size());
    t0 = std::chrono::high_resolution_clock::now();
    std::string decrypted = bob_ch.decrypt(payload);
    double dec_ms = ms_since(t0);
    std::cout << "[5] Bob decrypted message          " << dec_ms << " ms\n";
    std::cout << "    Result: \"" << decrypted << "\"\n";
    bool round_trip_ok = (decrypted == message);
    std::cout << "    Round-trip match: " << (round_trip_ok ? "YES ✓" : "NO ✗") << "\n\n";

    // ── Attack demo: flip a bit in ciphertext ─────────────────────────
    std::cout << "  ── Modification Attack Demo ──\n";
    EncryptedPayload tampered = payload;
    tampered.ciphertext[5] ^= 0xFF;  // flip bits
    std::string attack_result = bob_ch.decrypt(tampered);
    std::cout << "    Tampered decryption: " << attack_result << "\n\n";

    // ── Summary ───────────────────────────────────────────────────────
    double total_ms = keygen_ms + encap_ms + enc_ms + decap_ms + dec_ms;
    std::cout << "  ─────────────────────────────\n";
    std::cout << "  Total time: " << total_ms << " ms\n";
    std::cout << "  ─────────────────────────────\n";

    OQS_KEM_free(kem);
}

/* ─────────────────────────────────────────────────────────────────────────
   main
   ───────────────────────────────────────────────────────────────────────── */
int main(int argc, char* argv[]) {
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║   PQC C++ Core — Quantum-Resistant Hybrid Encryption Demo    ║\n";
    std::cout << "║   Kyber768 & McEliece + AES-256-GCM                          ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";

    std::string scheme  = (argc > 1) ? argv[1] : "kyber";
    std::string message = (argc > 2) ? argv[2] : "The quantum computer cannot break this!";

    std::cout << "\n  Message: \"" << message << "\"\n";

    if (scheme == "kyber" || scheme == "both") {
        run_scheme(OQS_KEM_alg_kyber_768, message);
    }
    if (scheme == "mceliece" || scheme == "both") {
        // Note: McEliece key generation can take 1-5 seconds — expected.
        run_scheme(OQS_KEM_alg_classic_mceliece_6960119, message);
    }
    if (scheme != "kyber" && scheme != "mceliece" && scheme != "both") {
        std::cerr << "\nUsage: " << argv[0] << " [kyber|mceliece|both] [\"message\"]\n";
        return 1;
    }

    std::cout << "\n[Done] All operations completed successfully.\n";
    return 0;
}
