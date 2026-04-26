# Quantum-Resistant Secure Communication

A comparative implementation of two post-quantum cryptographic schemes for secure two-party communication, designed to resist attacks from quantum computers using Shor's and Grover's algorithms.

## Project Overview

This project implements and compares two quantum-resistant secure communication protocols:
1. **Lattice-based scheme** using CRYSTALS-Kyber
2. **Code-based scheme** using Classic McEliece

Both implementations provide:
- **Confidentiality** - Encryption using post-quantum algorithms
- **Integrity** - Message authentication to detect modifications
- **Replay Protection** - Timestamp/nonce-based mechanisms
- **Performance Analysis** - Detailed metrics comparison

## Security Goals

Protection against:
- Data eavesdropping (even with quantum computers)
- Data modification attacks
- Replay attacks
- Future quantum computing threats (Shor's algorithm breaking RSA/ECC)

## Implemented Schemes

### Scheme 1: CRYSTALS-Kyber (Lattice-based)
- **Type:** IND-CCA2 secure KEM (Key Encapsulation Mechanism)
- **Security Level:** Kyber768 (NIST Level 3 ≈ AES-192)
- **Key Sizes:** Public key ~1184 bytes, Secret key ~2400 bytes
- **Ciphertext:** ~1088 bytes

### Scheme 2: Classic McEliece (Code-based)
- **Type:** IND-CCA2 secure encryption
- **Security Level:** mceliece6960119 (NIST Level 5 ≈ AES-256)
- **Key Sizes:** Public key ~1MB, Secret key ~13KB
- **Ciphertext:** ~226 bytes

## Architecture
Client A                        Client B
|                                  |
|-------- Key Generation --------->|
|<---- Public Key Exchange --------|
|--- Encrypt + MAC + Timestamp --> |
|<------- Verify + Decrypt --------|

## Technology Stack

- **Language:** Python 3.9+
- **Cryptography Libraries:**
  - `liboqs-python` - Open Quantum Safe library
  - `pycryptodome` - AES, HMAC implementations
  - `cryptography` - Additional utilities
- **Testing:** pytest
- **Performance:** timeit, memory_profiler

## Project Structure
quantum-resistant-secure-communication/
├── src/
│   ├── kyber_scheme.py          # Kyber-based implementation
│   ├── mceliece_scheme.py       # McEliece-based implementation
│   ├── secure_channel.py        # Common secure communication logic
│   └── utils.py                 # Helper functions
├── analysis/
│   ├── quantum_attack_analysis.md
│   └── performance_comparison.py
├── tests/
│   ├── test_kyber.py
│   └── test_mceliece.py
├── demos/
│   ├── demo_kyber.py
│   └── demo_mceliece.py
├── presentation/
│   └── slides.pptx
├── requirements.txt
└── README.md


## Installation

```bash
# Clone repository
git clone https://github.com/Alien0525/quantum-resistant-secure-communication.git
cd quantum-resistant-secure-communication

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Running Kyber-based Communication
```bash
python demos/demo_kyber.py
```

### Running McEliece-based Communication
```bash
python demos/demo_mceliece.py
```

### Performance Benchmarks
```bash
python analysis/performance_comparison.py
```

## Performance Comparison

| Metric | CRYSTALS-Kyber | Classic McEliece |
|--------|----------------|------------------|
| Public Key Size | ~1.2 KB | ~1 MB |
| Secret Key Size | ~2.4 KB | ~13 KB |
| Ciphertext Size | ~1.1 KB | ~226 bytes |
| Key Gen Time | ~0.5 ms | ~50 ms |
| Encryption Time | ~0.3 ms | ~1 ms |
| Decryption Time | ~0.4 ms | ~2 ms |

## Quantum Attack Analysis

**Shor's Algorithm Impact:**
- Breaks RSA-2048 in polynomial time (~O(n³))
- Requires ~20M physical qubits (with error correction)
- Timeline: Potentially 10-20 years

**Grover's Algorithm Impact:**
- Reduces AES-256 security to AES-128 equivalent
- Requires ~2^128 operations (vs ~2^256 classical)
- Mitigation: Use AES-256 with larger keys

**Why Post-Quantum Crypto:**
Both Kyber and McEliece resist known quantum algorithms because:
- Lattice problems (Kyber): No efficient quantum algorithm for SVP/LWE
- Coding theory (McEliece): Syndrome decoding remains hard

## Testing

```bash
pytest tests/ -v
```

## Implementation Details

### Security Features
1. **Hybrid Encryption:** KEM + AES-GCM for bulk data
2. **Authentication:** HMAC-SHA256 for integrity
3. **Replay Protection:** Timestamps with 60-second window
4. **Key Derivation:** HKDF for session keys

### Attack Protections
- **Eavesdropping:** Post-quantum encryption
- **Modification:** HMAC verification
- **Replay:** Timestamp validation + nonce tracking

## Live Data Visualization
We have plotted the comparison metrics using Chart.js. 
You can view the live interactive charts here: **[Link to your GitHub Pages URL]**

## Live Socket Demo
To test the live Client/Server architecture over localhost:

1. Open Terminal 1 (Server):
   ```bash
   python3 demos/server.py
2. Open Terminal 2 (Client):
    ```bash
    python3 demos/client.py
3. Begin chatting securely via Kyber768 + AES-256-GCM!

## References

- [NIST PQC Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [CRYSTALS-Kyber](https://pq-crystals.org/kyber/)
- [Classic McEliece](https://classic.mceliece.org/)
- [Open Quantum Safe](https://openquantumsafe.org/)

## Author

Aman NS - NYU CS6903 Cryptography Project

## License

MIT License - see LICENSE file for details