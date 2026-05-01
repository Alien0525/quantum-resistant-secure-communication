"""
Live Performance Benchmarking with Real-time Visualization.

This script benchmarks both schemes and generates JSON data for the web dashboard,
plus creates beautiful terminal visualizations.
"""
import oqs
import time
import json
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils import (
    print_banner, print_header, print_subheader, print_info, print_success,
    progress_bar, colored, Colors, format_bytes, format_time
)


def benchmark_scheme(kem_name, display_name, iterations=100):
    """
    Benchmark a KEM scheme with progress visualization.
    
    Args:
        kem_name: OQS KEM algorithm name
        display_name: Human-readable name
        iterations: Number of iterations for averaging
        
    Returns:
        dict: Comprehensive benchmark results
    """
    print_subheader(f"Benchmarking {display_name}")
    print_info(f"Running {iterations} iterations for accurate measurements...\n")
    
    results = {
        'scheme': display_name,
        'algorithm': kem_name,
        'iterations': iterations
    }
    
    times = {
        'keygen': [],
        'encap': [],
        'decap': []
    }
    
    with oqs.KeyEncapsulation(kem_name) as kem:
        # Benchmark each operation
        for i in range(iterations):
            # Key Generation
            start = time.perf_counter()
            pk = kem.generate_keypair()
            keygen_time = (time.perf_counter() - start) * 1000
            times['keygen'].append(keygen_time)
            
            sk = kem.export_secret_key()
            
            # Encapsulation
            start = time.perf_counter()
            ct, ss_sender = kem.encap_secret(pk)
            encap_time = (time.perf_counter() - start) * 1000
            times['encap'].append(encap_time)
            
            # Decapsulation
            start = time.perf_counter()
            ss_receiver = kem.decap_secret(ct)
            decap_time = (time.perf_counter() - start) * 1000
            times['decap'].append(decap_time)
            
            # Progress bar
            progress_bar(i + 1, iterations, 
                        prefix=f'Progress:', 
                        suffix=f'Complete ({i+1}/{iterations})', 
                        length=40)
        
        # Calculate statistics
        results['sizes'] = {
            'public_key': len(pk),
            'secret_key': len(sk),
            'ciphertext': len(ct),
            'shared_secret': len(ss_sender)
        }
        
        results['performance'] = {
            'keygen_avg_ms': sum(times['keygen']) / len(times['keygen']),
            'keygen_min_ms': min(times['keygen']),
            'keygen_max_ms': max(times['keygen']),
            'encap_avg_ms': sum(times['encap']) / len(times['encap']),
            'encap_min_ms': min(times['encap']),
            'encap_max_ms': max(times['encap']),
            'decap_avg_ms': sum(times['decap']) / len(times['decap']),
            'decap_min_ms': min(times['decap']),
            'decap_max_ms': max(times['decap']),
        }
        
        # Total time
        total_avg = (results['performance']['keygen_avg_ms'] + 
                    results['performance']['encap_avg_ms'] + 
                    results['performance']['decap_avg_ms'])
        results['performance']['total_avg_ms'] = total_avg
    
    print()
    print_success("Benchmark complete!\n")
    
    return results


def print_results_table(kyber_results, mceliece_results):
    """Print detailed comparison table."""
    print_header("Detailed Performance Analysis")
    
    # Size Comparison
    print(colored("\n📏 SIZE METRICS", Colors.BOLD + Colors.OKCYAN))
    print("─" * 85)
    print(f"{'Metric':<25} {'Kyber768':<25} {'McEliece':<25} {'Winner':<10}")
    print("─" * 85)
    
    size_metrics = [
        ('Public Key', 'public_key'),
        ('Secret Key', 'secret_key'),
        ('Ciphertext', 'ciphertext'),
    ]
    
    for name, key in size_metrics:
        k_val = kyber_results['sizes'][key]
        m_val = mceliece_results['sizes'][key]
        winner = "Kyber" if k_val < m_val else "McEliece"
        
        print(f"{name:<25} {format_bytes(k_val):<25} {format_bytes(m_val):<25} "
              f"{colored('✓ ' + winner, Colors.OKGREEN):<10}")
    
    # Performance Comparison
    print(colored("\n⚡ PERFORMANCE METRICS (Average)", Colors.BOLD + Colors.OKCYAN))
    print("─" * 85)
    print(f"{'Operation':<25} {'Kyber768':<25} {'McEliece':<25} {'Winner':<10}")
    print("─" * 85)
    
    perf_metrics = [
        ('Key Generation', 'keygen_avg_ms'),
        ('Encapsulation', 'encap_avg_ms'),
        ('Decapsulation', 'decap_avg_ms'),
        ('TOTAL', 'total_avg_ms'),
    ]
    
    for name, key in perf_metrics:
        k_val = kyber_results['performance'][key]
        m_val = mceliece_results['performance'][key]
        winner = "Kyber" if k_val < m_val else "McEliece"
        
        k_str = format_time(k_val)
        m_str = format_time(m_val)
        
        if name == 'TOTAL':
            print("─" * 85)
        
        print(f"{name:<25} {k_str:<25} {m_str:<25} "
              f"{colored('✓ ' + winner, Colors.OKGREEN):<10}")
    
    print("─" * 85)
    
    # Speedup analysis
    print(colored("\n📊 RELATIVE PERFORMANCE", Colors.BOLD + Colors.OKCYAN))
    print("─" * 60)
    
    speedups = {
        'Key Generation': mceliece_results['performance']['keygen_avg_ms'] / kyber_results['performance']['keygen_avg_ms'],
        'Encapsulation': mceliece_results['performance']['encap_avg_ms'] / kyber_results['performance']['encap_avg_ms'],
        'Decapsulation': mceliece_results['performance']['decap_avg_ms'] / kyber_results['performance']['decap_avg_ms'],
    }
    
    for op, speedup in speedups.items():
        print(f"Kyber is {colored(f'{speedup:.1f}x', Colors.OKGREEN)} faster than McEliece at {op}")
    
    print()


def save_to_json(kyber_results, mceliece_results, output_file='benchmark_results.json'):
    """Save results to JSON and inject inline into dashboard.html for file:// compatibility."""
    data = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'schemes': {
            'kyber': kyber_results,
            'mceliece': mceliece_results
        }
    }

    docs_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'docs'
    )

    # Save standalone JSON file
    output_path = os.path.join(docs_dir, output_file)
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)
    print_success(f"Results saved to: {output_path}")

    # Inject data inline into dashboard.html so it works via file:// (no CORS issues)
    dashboard_path = os.path.join(docs_dir, 'dashboard.html')
    if os.path.exists(dashboard_path):
        with open(dashboard_path, 'r') as f:
            html = f.read()

        inline_tag = '<!-- BENCHMARK_DATA_INLINE -->'
        inline_script = (
            f'{inline_tag}\n'
            f'<script id="benchmarkData" type="application/json">\n'
            f'{json.dumps(data, indent=2)}\n'
            f'</script>'
        )

        import re
        if inline_tag in html:
            # Replace existing inline block
            html = re.sub(
                r'<!-- BENCHMARK_DATA_INLINE -->.*?</script>',
                inline_script,
                html,
                flags=re.DOTALL
            )
        else:
            # First run: inject before </head>
            html = html.replace('</head>', inline_script + '\n</head>', 1)

        with open(dashboard_path, 'w') as f:
            f.write(html)
        print_success(f"Data injected into dashboard: {dashboard_path}")


def main():
    """Main benchmarking function."""
    print_banner()
    print_header("Quantum-Resistant Cryptography Performance Benchmark")
    
    print_info("This benchmark will test both schemes with multiple iterations")
    print_info("to provide accurate performance measurements.\n")
    
    # Benchmark Kyber (fast, so more iterations)
    kyber_results = benchmark_scheme("Kyber768", "CRYSTALS-Kyber768", iterations=1000)
    
    # Benchmark McEliece (slower key generation, fewer iterations)
    mceliece_results = benchmark_scheme("Classic-McEliece-6960119", "Classic McEliece", iterations=50)
    
    # Display results
    print_results_table(kyber_results, mceliece_results)
    
    # Save to JSON
    save_to_json(kyber_results, mceliece_results)
    
    print()
    print_success("Benchmark complete! Data saved for web dashboard.")
    print_info("Open docs/dashboard.html to view interactive visualizations.")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        print(colored("\nBenchmark interrupted by user.", Colors.WARNING))
        print()
        sys.exit(0)
