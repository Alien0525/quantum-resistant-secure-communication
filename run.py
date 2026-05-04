#!/usr/bin/env python3
"""
Master launcher for Quantum-Resistant Cryptography Demo.

This script provides a unified entry point for all demonstrations.
"""
import sys
import os
import subprocess
from pathlib import Path


def print_banner():
    """Print main banner."""
    banner = """
    ╔═══════════════════════════════════════════════════════════════════╗
    ║                                                                   ║
    ║     ██████╗  ██████╗  ██████╗    ███████╗███████╗ ██████╗        ║
    ║     ██╔══██╗██╔═══██╗██╔════╝    ██╔════╝██╔════╝██╔════╝        ║
    ║     ██████╔╝██║   ██║██║         ███████╗█████╗  ██║             ║
    ║     ██╔═══╝ ██║▄▄ ██║██║         ╚════██║██╔══╝  ██║             ║
    ║     ██║     ╚██████╔╝╚██████╗    ███████║███████╗╚██████╗        ║
    ║     ╚═╝      ╚══▀▀═╝  ╚═════╝    ╚══════╝╚══════╝ ╚═════╝        ║
    ║                                                                   ║
    ║         Quantum-Resistant Secure Communication System            ║
    ║                      Master Launcher v1.0                        ║
    ║                                                                   ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def main_menu():
    """Display main menu."""
    print("\n" + "="*70)
    print("  MAIN MENU - Choose Your Demonstration")
    print("="*70 + "\n")
    
    print("  📚 EDUCATIONAL DEMOS:")
    print("    1. Interactive Demo (Best for learning)")
    print("    2. Video Demo (Automated presentation)")
    print()
    
    print("  💬 LIVE COMMUNICATION:")
    print("    3. Start Chat Server")
    print("    4. Start Chat Client")
    print()
    
    print("  📊 ANALYSIS & BENCHMARKING:")
    print("    5. Run Performance Benchmark")
    print("    6. Open Web Dashboard")
    print()
    
    print("  🧪 TESTING:")
    print("    7. Run Test Suite")
    print("    8. Quick Installation Check")
    print()
    
    print("  📖 DOCUMENTATION:")
    print("    9. View README")
    print("    10. View Quick Start Guide")
    print()
    
    print("  0. Exit")
    print()


def run_script(script_path, description):
    """Run a Python script."""
    print(f"\n{'='*70}")
    print(f"  {description}")
    print(f"{'='*70}\n")
    
    try:
        subprocess.run([sys.executable, script_path], check=True)
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Error running {script_path}: {e}")
    except KeyboardInterrupt:
        print(f"\n⚠️  {description} interrupted by user.")


def open_browser(url):
    """Open URL in default browser."""
    import webbrowser
    print(f"\n📂 Opening {url} in browser...")
    webbrowser.open(url)


def view_file(filepath):
    """View a text file."""
    print(f"\n{'='*70}")
    print(f"  Viewing: {filepath}")
    print(f"{'='*70}\n")
    
    try:
        with open(filepath, 'r') as f:
            content = f.read()
            print(content)
    except Exception as e:
        print(f"❌ Error reading file: {e}")
    
    input("\nPress ENTER to continue...")


def main():
    """Main launcher function."""
    # Get project root directory
    project_root = Path(__file__).parent.absolute()
    
    while True:
        os.system('clear' if os.name != 'nt' else 'cls')
        print_banner()
        main_menu()
        
        choice = input("👉 Enter your choice (0-10): ").strip()
        
        if choice == '1':
            run_script(project_root / 'demos' / 'interactive_demo.py', 
                      "Interactive Educational Demo")
        
        elif choice == '2':
            run_script(project_root / 'demos' / 'video_demo.py',
                      "Automated Video Demonstration")
        
        elif choice == '3':
            print("\n📡 Starting Chat Server...")
            print("💡 Tip: Open another terminal and run option 4 to connect\n")
            run_script(project_root / 'demos' / 'server.py',
                      "PQC Secure Chat Server")
        
        elif choice == '4':
            print("\n💬 Starting Chat Client...")
            print("💡 Tip: Make sure server is running first (option 3)\n")
            run_script(project_root / 'demos' / 'client.py',
                      "PQC Secure Chat Client")
        
        elif choice == '5':
            print("\n⚡ Running Performance Benchmark...")
            print("💡 This will take 1-2 minutes. Results saved to docs/benchmark_results.json\n")
            run_script(project_root / 'analysis' / 'live_benchmark.py',
                      "Performance Benchmarking")
        
        elif choice == '6':
            dashboard_path = project_root / 'docs' / 'dashboard.html'
            if dashboard_path.exists():
                open_browser(f'file://{dashboard_path}')
                print("✅ Dashboard opened in browser")
                input("\nPress ENTER to continue...")
            else:
                print("\n❌ Dashboard not found. Run benchmark first (option 5).")
                input("\nPress ENTER to continue...")
        
        elif choice == '7':
            run_script(project_root / 'tests' / 'test_complete.py',
                      "Complete Test Suite")
        
        elif choice == '8':
            print("\n🔍 Running Quick Installation Check...\n")
            try:
                import oqs
                from src.base_protocol import KyberProtocol
                from Crypto.Cipher import AES
                
                print("✅ liboqs-python: OK")
                print(f"   Version: {oqs.oqs_version()}")
                
                print("✅ PyCryptodome: OK")
                
                print("✅ Project modules: OK")
                
                print("\n🎉 All checks passed! System ready.")
            except Exception as e:
                print(f"❌ Installation check failed: {e}")
                print("\n💡 See QUICKSTART.md for installation instructions")
            
            input("\nPress ENTER to continue...")
        
        elif choice == '9':
            view_file(project_root / 'README.md')
        
        elif choice == '10':
            view_file(project_root / 'QUICKSTART.md')
        
        elif choice == '0':
            print("\n👋 Thank you for using PQC Secure Communication!")
            print("🌟 Star the project on GitHub if you found it useful!\n")
            sys.exit(0)
        
        else:
            print("\n❌ Invalid choice. Please enter 0-10.")
            input("\nPress ENTER to continue...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Launcher interrupted. Goodbye!")
        sys.exit(0)
