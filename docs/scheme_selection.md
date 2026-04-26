# Scheme Selection Rationale

## Chosen Schemes

### 1. CRYSTALS-Kyber768 (Lattice-based)
**Selection Reason:**
- NIST standardized (2024)
- Balanced security (Level 3) and performance
- Smaller key sizes compared to McEliece
- Well-supported by liboqs library

**Technical Details:**
- Public Key: 1184 bytes
- Secret Key: 2400 bytes
- Ciphertext: 1088 bytes
- Security: Based on Module-LWE hardness
- Attack Resistance: No known quantum speedup for lattice problems

### 2. Classic McEliece6960119 (Code-based)
**Selection Reason:**
- Conservative security choice (Level 5)
- Longest-studied post-quantum scheme (since 1978)
- Different mathematical foundation (diversity)
- Demonstrates tradeoff: security vs. key size

**Technical Details:**
- Public Key: ~1,044,992 bytes (~1 MB)
- Secret Key: 13,932 bytes
- Ciphertext: 226 bytes
- Security: Based on syndrome decoding
- Attack Resistance: Coding-theory problems resist quantum attacks

## Comparison Matrix

| Feature | Kyber768 | McEliece6960119 |
|---------|----------|-----------------|
| Mathematical Basis | Lattices (LWE) | Coding Theory |
| NIST Security Level | 3 (≈AES-192) | 5 (≈AES-256) |
| Public Key Size | Small (1.2KB) | Large (1MB) |
| Ciphertext Size | Medium (1.1KB) | Small (226B) |
| Speed | Very Fast | Fast |
| Maturity | New (2016) | Old (1978) |
| Standardization | NIST 2024 | NIST Finalist |

## Why These Choices Meet Requirements

**Requirement (a):** One from each family ✓
- Kyber = Lattice-based
- McEliece = Code-based

**Alternative Compliance (b):** Using NIST-approved schemes ✓
- Both are from NIST PQC competition
- Kyber is standardized
- McEliece is finalist

**Diversity Benefit:**
- Different attack surfaces
- If one family has weakness discovered, the other remains secure
- Demonstrates range of post-quantum approaches