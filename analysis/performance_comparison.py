import oqs
import time

def benchmark_kem(kem_name, iterations):
    print(f"Benchmarking {kem_name} over {iterations} iterations...")
    results = {}
    
    with oqs.KeyEncapsulation(kem_name) as kem:
        # 1. Benchmark Key Generation (Receiver)
        start = time.time()
        for _ in range(iterations):
            pk = kem.generate_keypair()
        results['keygen_time'] = ((time.time() - start) / iterations) * 1000 # convert to ms
        
        sk = kem.export_secret_key()
        results['pk_size'] = len(pk)
        results['sk_size'] = len(sk)
        
        # 2. Benchmark Encapsulation (Sender)
        start = time.time()
        for _ in range(iterations):
            ct, ss = kem.encap_secret(pk)
        results['encap_time'] = ((time.time() - start) / iterations) * 1000 # ms
        results['ct_size'] = len(ct)
        
        # 3. Benchmark Decapsulation (Receiver)
        start = time.time()
        for _ in range(iterations):
            kem.decap_secret(ct)
        results['decap_time'] = ((time.time() - start) / iterations) * 1000 # ms
        
    return results

def main():
    print("Gathering performance metrics...\n")
    
    # Kyber is fast, so we can do 1000 iterations for a highly accurate average
    kyber_stats = benchmark_kem("Kyber768", iterations=1000)
    
    # McEliece is slow to generate keys, so we only do 10 iterations
    mceliece_stats = benchmark_kem("Classic-McEliece-6960119", iterations=10)
    
    print("\n" + "="*80)
    print(f"{'Metric':<25} | {'CRYSTALS-Kyber768':<25} | {'Classic McEliece':<25}")
    print("="*80)
    
    # Size metrics
    print(f"{'Public Key Size':<25} | {kyber_stats['pk_size']:<15} bytes     | {mceliece_stats['pk_size']:<15} bytes")
    print(f"{'Secret Key Size':<25} | {kyber_stats['sk_size']:<15} bytes     | {mceliece_stats['sk_size']:<15} bytes")
    print(f"{'Ciphertext Size':<25} | {kyber_stats['ct_size']:<15} bytes     | {mceliece_stats['ct_size']:<15} bytes")
    print("-" * 80)
    
    # Speed metrics
    print(f"{'Key Gen Time (Receiver)':<25} | {kyber_stats['keygen_time']:<15.3f} ms        | {mceliece_stats['keygen_time']:<15.3f} ms")
    print(f"{'Encap Time (Sender)':<25} | {kyber_stats['encap_time']:<15.3f} ms        | {mceliece_stats['encap_time']:<15.3f} ms")
    print(f"{'Decap Time (Receiver)':<25} | {kyber_stats['decap_time']:<15.3f} ms        | {mceliece_stats['decap_time']:<15.3f} ms")
    print("="*80)

if __name__ == "__main__":
    main()