# Quantum Attack Analysis on Modern Cryptography

## 1. Shor's Algorithm
**Target:** Public-key cryptography (RSA, ECC, Diffie-Hellman)
**Mechanism:** Shor's algorithm solves integer factorization and the discrete logarithm problem in polynomial time (specifically $O(n^3)$ operations) on a quantum computer. 
**Impact:** - Completely breaks NSA Suite B public-key algorithms (like ECDSA and ECDH).
- To break RSA-2048, a quantum computer would need roughly 4,096 logical qubits. Due to quantum noise, this requires approximately 20 million *physical* qubits with error correction.
- Current timeline estimates suggest a Cryptographically Relevant Quantum Computer (CRQC) capable of this might exist within 10-20 years.

## 2. Grover's Algorithm
**Target:** Symmetric-key cryptography (AES) and Hash functions (SHA)
**Mechanism:** Grover's algorithm provides a quadratic speedup for unstructured search problems. It can search an $N$-element database in $\sqrt{N}$ time.
**Impact:**
- Reduces the effective security of symmetric algorithms by half. 
- AES-128 is reduced to 64-bit security (which is vulnerable).
- AES-256 is reduced to 128-bit security (which remains secure against foreseeable quantum attacks).
- **Mitigation:** The NSA Suite B recommendation to mitigate Grover's algorithm is simply to double symmetric key sizes (e.g., transition from AES-128 to AES-256).

## 3. Post-Quantum Mitigation (Our Approach)
To protect against these attacks, this project implements:
1. **CRYSTALS-Kyber (Lattice-based):** Relies on the Module Learning With Errors (MLWE) problem. There are no known quantum algorithms that offer exponential or quadratic speedups against lattice problems.
2. **Classic McEliece (Code-based):** Relies on the hardness of decoding general linear codes (Syndrome Decoding Problem). It has withstood cryptographic analysis since 1978 and remains secure against Shor's algorithm.