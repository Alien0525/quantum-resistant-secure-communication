# C++ Extra Credit — PQC Core Implementation

This directory contains a standalone C++ implementation of the quantum-resistant
hybrid encryption scheme for the extra-credit requirement of CS6903/4783 Project 3.5.

## What It Does

`pqc_core.cpp` implements the **identical protocol** as `src/base_protocol.py` + `src/secure_channel.py`, but in C++:

1. **KEM key generation** — Bob generates a Kyber768 or McEliece keypair via liboqs
2. **Encapsulation** — Alice encapsulates a shared secret using Bob's public key
3. **HKDF-SHA256 key derivation** — shared secret → 256-bit AES key (matches Python HKDF)
4. **AES-256-GCM encryption** — Alice encrypts the message (OpenSSL EVP API)
5. **Decapsulation** — Bob recovers the shared secret
6. **AES-256-GCM decryption + verification** — Bob decrypts and verifies the auth tag
7. **Modification attack demo** — bit-flip triggers GCM auth failure

## Build

### macOS (Homebrew)
```bash
brew install liboqs openssl@3
make
```

### Ubuntu/Debian
```bash
sudo apt install liboqs-dev libssl-dev build-essential
make
```

## Usage
```bash
# Run with Kyber768
./pqc_core kyber "Transfer $1000 to Account #12345"

# Run with Classic McEliece (key generation takes ~1-5 seconds — expected)
./pqc_core mceliece "Transfer $1000 to Account #12345"

# Run both schemes back-to-back
./pqc_core both "Transfer $1000 to Account #12345"
```

## Design Notes

- **SecureChannel class** mirrors `src/secure_channel.py` exactly: HKDF salt and info
  strings are identical so both implementations produce compatible keys from the same
  shared secret.
- The C++ code uses OpenSSL's `EVP_KDF` (HKDF, OpenSSL 3.x API) — ensure OpenSSL ≥ 3.0.
- The benchmarking, dashboard, and chat demo use the Python implementation.
  This C++ file exists to demonstrate the core algorithm implementation.

## Files
| File | Description |
|------|-------------|
| `pqc_core.cpp` | Full C++ implementation — KEM + AES-256-GCM hybrid scheme |
| `Makefile` | Auto-detects macOS / Linux build environment |
| `README.md` | This file |
