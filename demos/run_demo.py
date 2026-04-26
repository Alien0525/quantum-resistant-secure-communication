import sys
import os
import time

# Add the parent directory to the path so we can import src
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.kyber_scheme import KyberProtocol
from src.mceliece_scheme import McElieceProtocol

def main():
    message = "TOP SECRET: The coordinates to the rebel base are 40.7128 N, 74.0060 W"
    
    print("="*60)
    print("QUANTUM-RESISTANT SECURE COMMUNICATION DEMO")
    print("="*60)
    
    # Run Kyber
    start_time = time.time()
    kyber = KyberProtocol()
    kyber.run_secure_communication(message)
    print(f"Kyber execution time: {(time.time() - start_time):.4f} seconds\n")
    
    # Run McEliece
    start_time = time.time()
    mceliece = McElieceProtocol()
    mceliece.run_secure_communication(message)
    print(f"McEliece execution time: {(time.time() - start_time):.4f} seconds\n")

if __name__ == "__main__":
    main()