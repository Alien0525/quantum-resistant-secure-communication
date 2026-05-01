"""
Automated demo script for video recording.

This script runs through all demonstrations automatically with pauses
for explanation, making it perfect for screen recording.
"""
import sys
import os
import time
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.base_protocol import KyberProtocol, McElieceProtocol
from src.secure_channel import SecureChannel
from src.utils import (
    print_banner, print_header, print_subheader, print_info, print_success,
    print_warning, print_error, print_attack, hexdump, colored, Colors,
    clear_screen, animate_encryption
)
import oqs


def pause(seconds=2, message=""):
    """Pause for video narration."""
    if message:
        print(colored(f"\n[Narrator: {message}]", Colors.GRAY + Colors.BOLD))
    time.sleep(seconds)


def demo_introduction():
    """Introduction slide."""
    clear_screen()
    print_banner()
    
    print_header("Welcome to Quantum-Resistant Cryptography Demo")
    print()
    print(colored("  This demonstration showcases:", Colors.BOLD))
    print()
    print("  ✓ Post-quantum secure communication")
    print("  ✓ Protection against quantum computer attacks")
    print("  ✓ Attack prevention mechanisms")
    print("  ✓ Performance comparison")
    print()
    print(colored("  Schemes Demonstrated:", Colors.BOLD))
    print("  • CRYSTALS-Kyber768 (Lattice-based)")
    print("  • Classic McEliece (Code-based)")
    print()
    
    pause(5, "Introduce yourself and the project objectives")


def demo_quick_communication():
    """Quick demonstration of both schemes."""
    clear_screen()
    print_header("Demo 1: Secure Communication")
    
    pause(2, "Explain we're sending a secret message")
    
    message = "The nuclear launch codes are: ALPHA-7734-OMEGA"
    print_info(f"Secret Message: '{message}'")
    print()
    
    pause(2, "Show the plaintext message")
    
    # Kyber
    print_subheader("Using CRYSTALS-Kyber768")
    pause(1, "Explain Kyber is lattice-based, NIST standardized")
    
    kyber = KyberProtocol()
    k_results = kyber.run_secure_communication(message, verbose=True)
    
    pause(3, "Point out the speed and small ciphertext")
    
    # McEliece
    print_subheader("Using Classic McEliece")
    pause(1, "Explain McEliece is code-based, very conservative")
    
    mceliece = McElieceProtocol()
    m_results = mceliece.run_secure_communication(message, verbose=True)
    
    pause(3, "Note the large public key but tiny ciphertext")
    
    # Comparison
    print_header("Quick Comparison")
    print(f"{'Metric':<30} {'Kyber':<20} {'McEliece':<20}")
    print("─" * 70)
    print(f"{'Public Key Size':<30} {k_results['pk_size']:,} bytes       {m_results['pk_size']:,} bytes")
    print(f"{'KEM Ciphertext Size':<30} {k_results['ct_size']:,} bytes       {m_results['ct_size']:,} bytes")
    print(f"{'Total Time':<30} {k_results['total_time']:.2f} ms          {m_results['total_time']:.2f} ms")
    print()
    
    pause(5, "Highlight the tradeoffs between the schemes")


def demo_visual_encryption():
    """Visual demonstration of encryption process."""
    clear_screen()
    print_header("Demo 2: What Happens During Encryption?")
    
    pause(2, "Show step-by-step encryption process")
    
    with oqs.KeyEncapsulation("Kyber768") as kem:
        # Step 1
        print_info("Step 1: Bob generates keypair")
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
        print(f"  Public Key ({len(pk)} bytes):")
        print(hexdump(pk[:64], prefix="    "))
        print()
        pause(3, "Public key can be shared openly")
        
        # Step 2
        print_info("Step 2: Alice encapsulates shared secret")
        ct, shared_secret = kem.encap_secret(pk)
        print(f"  Ciphertext ({len(ct)} bytes):")
        print(hexdump(ct[:64], prefix="    "))
        print()
        pause(3, "Ciphertext travels over insecure network")
        
        # Step 3
        print_info("Step 3: Bob decapsulates with secret key")
        recovered = kem.decap_secret(ct)
        print(f"  Shared Secret ({len(shared_secret)} bytes):")
        print(hexdump(shared_secret[:32], prefix="    "))
        print()
        print_success(f"  Secrets match: {shared_secret == recovered}")
        print()
        pause(3, "Both parties now have the same shared secret")
        
        # Step 4
        print_info("Step 4: Encrypt message with AES-256-GCM")
        channel = SecureChannel(shared_secret)
        message = "Top secret message!"
        encrypted = channel.encrypt_message(message)
        
        print(f"  Plaintext:  {message}")
        print(f"  Encrypted:")
        print(hexdump(encrypted['ciphertext'], prefix="    "))
        print()
        pause(3, "AES provides the actual data encryption")


def demo_attack_replay():
    """Demonstrate replay attack prevention."""
    clear_screen()
    print_header("Demo 3: Replay Attack Prevention")
    
    pause(2, "Attacker intercepts and replays old message")
    
    with oqs.KeyEncapsulation("Kyber768") as kem:
        pk = kem.generate_keypair()
        ct, shared_secret = kem.encap_secret(pk)
        channel = SecureChannel(shared_secret)
        
        # Original message
        msg = "Transfer $1000 to account #12345"
        encrypted = channel.encrypt_message(msg)
        
        print_success(f"Original Message: '{msg}'")
        print_info(f"Timestamp: {int(time.time())}")
        print()
        pause(2, "Legitimate transaction is sent")
        
        # Legitimate decryption
        print_info("Receiver processes message...")
        decrypted = channel.decrypt_message(encrypted)
        print_success(f"✓ Processed: '{decrypted}'")
        print()
        pause(2, "Transaction completes successfully")
        
        # Replay attack
        print_attack("ATTACKER intercepts the encrypted message!")
        print_warning("Waiting 3 seconds...")
        for i in range(3):
            time.sleep(1)
            print(f"  {i+1}...")
        print()
        
        print_attack("Replaying captured message...")
        result = channel.decrypt_message(encrypted)
        
        if "already used" in result.lower() or "failed" in result.lower():
            print_success("✓✓✓ REPLAY ATTACK BLOCKED! ✓✓✓")
            print_info(f"Reason: {result}")
            print()
            pause(4, "Nonce tracking prevents replay attacks")
        else:
            print_error("Attack succeeded (shouldn't happen)")


def demo_attack_modification():
    """Demonstrate modification attack prevention."""
    clear_screen()
    print_header("Demo 4: Message Modification Attack")
    
    pause(2, "Attacker tries to modify encrypted message")
    
    with oqs.KeyEncapsulation("Kyber768") as kem:
        pk = kem.generate_keypair()
        ct, shared_secret = kem.encap_secret(pk)
        channel = SecureChannel(shared_secret)
        
        # Original
        msg = "Transfer $100"
        encrypted = channel.encrypt_message(msg)
        
        print_success(f"Original: '{msg}'")
        print(f"\nOriginal Ciphertext:")
        print(hexdump(encrypted['ciphertext'][:48], prefix="  "))
        print()
        pause(3, "Legitimate encrypted message")
        
        # Attack
        print_attack("ATTACKER: Trying to change $100 to $999!")
        print_warning("Flipping random bits in ciphertext...")
        
        modified_ct = bytearray(encrypted['ciphertext'])
        for i in range(5, 15):  # Flip 10 bytes
            if i < len(modified_ct):
                modified_ct[i] ^= 0xFF
        
        print(f"\nModified Ciphertext:")
        print(hexdump(bytes(modified_ct)[:48], prefix="  "))
        print()
        pause(3, "Bits have been flipped")
        
        # Try to decrypt
        print_attack("Attempting to decrypt modified message...")
        modified_payload = {
            'ciphertext': bytes(modified_ct),
            'tag': encrypted['tag'],
            'nonce': encrypted['nonce'],
            'timestamp': encrypted['timestamp']
        }
        
        result = channel.decrypt_message(modified_payload)
        
        if "FAILED" in result:
            print_success("✓✓✓ MODIFICATION BLOCKED! ✓✓✓")
            print_info(f"Reason: {result}")
            print()
            pause(4, "GCM authentication tag detects tampering")
        else:
            print_error(f"Attack succeeded: {result}")


def demo_quantum_threat():
    """Explain quantum computing threat."""
    clear_screen()
    print_header("Demo 5: The Quantum Threat")
    
    pause(2, "Why do we need post-quantum crypto?")
    
    print_subheader("Classical RSA-2048")
    print(colored("  Current Status: ", Colors.BOLD) + colored("SECURE", Colors.OKGREEN))
    print(f"  Classical Attack: ~2^112 operations (infeasible)")
    print()
    pause(3, "RSA is secure against classical computers")
    
    print(colored("  With Quantum Computer:", Colors.BOLD))
    print(colored("  Status: BROKEN!", Colors.FAIL + Colors.BOLD))
    print(f"  Shor's Algorithm: ~O(n³) operations (feasible)")
    print()
    pause(3, "Shor's algorithm breaks RSA in polynomial time")
    
    print_warning("  Quantum Requirements:")
    print("    • Logical Qubits: ~4,000")
    print("    • Physical Qubits: ~20,000,000")
    print("    • Timeline: 10-20 years")
    print()
    pause(4, "Large quantum computers are coming")
    
    print_subheader("Post-Quantum Solutions")
    
    print(colored("\n  CRYSTALS-Kyber (Lattice-based)", Colors.OKGREEN + Colors.BOLD))
    print("    • Based on: Module-LWE problem")
    print("    • Classical: ~2^192 operations")
    print("    • Quantum: ~2^192 operations (NO SPEEDUP!)")
    print("    • Why secure: No efficient quantum algorithm for LWE")
    print()
    pause(4, "Lattice problems resist quantum attacks")
    
    print(colored("  Classic McEliece (Code-based)", Colors.OKGREEN + Colors.BOLD))
    print("    • Based on: Syndrome decoding")
    print("    • Classical: ~2^256 operations")
    print("    • Quantum: ~2^256 operations (NO SPEEDUP!)")
    print("    • Why secure: Coding theory problems remain hard")
    print()
    pause(4, "Most conservative post-quantum option")


def demo_conclusion():
    """Conclusion and summary."""
    clear_screen()
    print_header("Conclusion & Key Takeaways")
    
    print(colored("\n  ✓ Successfully Demonstrated:", Colors.BOLD + Colors.OKGREEN))
    print("    • Two NIST-approved post-quantum schemes")
    print("    • Full end-to-end encrypted communication")
    print("    • Protection against replay attacks")
    print("    • Protection against modification attacks")
    print("    • Quantum-resistant security properties")
    print()
    
    pause(3, "Summarize what was shown")
    
    print(colored("  📊 Performance Summary:", Colors.BOLD + Colors.OKCYAN))
    print("    • Kyber: Fast, small keys, practical")
    print("    • McEliece: Conservative, tiny ciphertext, large keys")
    print()
    
    pause(3, "Both are viable for different use cases")
    
    print(colored("  🔮 Future of Cryptography:", Colors.BOLD + Colors.HEADER))
    print("    • Transition to PQC is happening NOW")
    print("    • NIST standardization complete (2024)")
    print("    • Hybrid classical+PQ schemes emerging")
    print("    • Critical for long-term data security")
    print()
    
    pause(4, "Emphasize urgency of migration")
    
    print_header("Thank You!")
    print()
    print(colored("  Questions?", Colors.BOLD + Colors.OKCYAN))
    print()
    print(colored("  Repository: github.com/yourusername/quantum-resistant-crypto", Colors.GRAY))
    print(colored("  Documentation: See README.md", Colors.GRAY))
    print()
    
    pause(3, "Thank the audience and invite questions")


def main():
    """Run complete automated demo."""
    print()
    print(colored("=" * 70, Colors.OKCYAN))
    print(colored("AUTOMATED DEMO SCRIPT FOR VIDEO RECORDING", Colors.BOLD + Colors.HEADER).center(80))
    print(colored("=" * 70, Colors.OKCYAN))
    print()
    print(colored("This will run through all demonstrations with pauses.", Colors.WARNING))
    print(colored("Perfect for screen recording your presentation!", Colors.WARNING))
    print()
    input(colored("Press ENTER to start recording... ", Colors.OKCYAN + Colors.BOLD))
    
    # Run all demos
    demo_introduction()
    demo_quick_communication()
    demo_visual_encryption()
    demo_attack_replay()
    demo_attack_modification()
    demo_quantum_threat()
    demo_conclusion()
    
    print()
    print(colored("=" * 70, Colors.OKGREEN))
    print(colored("DEMO COMPLETE - STOP RECORDING", Colors.BOLD + Colors.OKGREEN).center(80))
    print(colored("=" * 70, Colors.OKGREEN))
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        print(colored("\nDemo interrupted. Recording stopped.", Colors.WARNING))
        print()
        sys.exit(0)
