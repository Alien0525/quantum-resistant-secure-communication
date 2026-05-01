"""
Interactive demonstration of quantum-resistant cryptography with attack simulations.

This script provides a visual, interactive demonstration including:
- Normal secure communication
- Replay attack detection
- Message modification attack detection
- Eavesdropping protection visualization
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
    print_comparison_table, clear_screen, press_enter_to_continue,
    animate_encryption, progress_bar
)
import oqs


def demo_normal_communication():
    """Demonstrate normal secure communication."""
    print_header("Demonstration 1: Normal Secure Communication")
    
    message = "The quantum computer cannot break this encryption!"
    
    print_info("Testing CRYSTALS-Kyber768...")
    kyber = KyberProtocol()
    k_results = kyber.run_secure_communication(message, verbose=True)
    
    print_subheader("Now testing Classic McEliece")
    mceliece = McElieceProtocol()
    m_results = mceliece.run_secure_communication(message, verbose=False)  # Less verbose
    
    print_comparison_table(k_results, m_results)
    
    press_enter_to_continue()


def demo_replay_attack():
    """Demonstrate replay attack prevention."""
    print_header("Demonstration 2: Replay Attack Prevention")
    
    print_info("Scenario: Attacker intercepts encrypted message and tries to replay it")
    print()
    
    # Setup
    kyber = KyberProtocol()
    
    with oqs.KeyEncapsulation("Kyber768") as kem:
        public_key = kem.generate_keypair()
        ciphertext, shared_secret = kem.encap_secret(public_key)
        
        channel = SecureChannel(shared_secret)
        
        # Original message
        original_msg = "Transfer $1000 to Account #12345"
        encrypted = channel.encrypt_message(original_msg)
        
        print_success(f"Original Message: '{original_msg}'")
        print_info(f"Encrypted at timestamp: {int(time.time())}")
        print(f"\n{hexdump(encrypted['ciphertext'][:32])}\n")
        
        # Legitimate decryption
        print_info("Legitimate recipient decrypts message...")
        decrypted = channel.decrypt_message(encrypted)
        print_success(f"Decrypted: '{decrypted}'\n")
        
        # Replay attack
        print_attack("ATTACKER: Intercepted message! Attempting replay attack...")
        time.sleep(1)
        
        print_warning("Sleeping 2 seconds to simulate delayed replay...")
        for i in range(2):
            progress_bar(i + 1, 2, prefix='Waiting:', suffix='Complete', length=40)
            time.sleep(1)
        
        print_attack("Replaying captured message...")
        replay_result = channel.decrypt_message(encrypted)
        
        if "Nonce already used" in replay_result or "DECRYPTION FAILED" in replay_result:
            print_success("✓ Replay attack BLOCKED! Message rejected due to duplicate nonce")
            print_info(f"Reason: {replay_result}")
        else:
            print_error("✗ Replay attack succeeded (This shouldn't happen!)")
    
    print()
    press_enter_to_continue()


def demo_modification_attack():
    """Demonstrate message modification attack prevention."""
    print_header("Demonstration 3: Message Modification Attack Prevention")
    
    print_info("Scenario: Attacker intercepts and modifies encrypted message")
    print()
    
    with oqs.KeyEncapsulation("Kyber768") as kem:
        public_key = kem.generate_keypair()
        ciphertext, shared_secret = kem.encap_secret(public_key)
        
        channel = SecureChannel(shared_secret)
        
        # Original message
        original_msg = "Transfer $100 to Account #12345"
        encrypted = channel.encrypt_message(original_msg)
        
        print_success(f"Original Message: '{original_msg}'")
        print(f"\n{hexdump(encrypted['ciphertext'][:48])}\n")
        
        # Attacker modifies ciphertext
        print_attack("ATTACKER: Attempting to modify ciphertext...")
        print_warning("Flipping bits 10-15 in ciphertext...")
        
        modified_ct = bytearray(encrypted['ciphertext'])
        for i in range(10, 16):
            if i < len(modified_ct):
                modified_ct[i] ^= 0xFF  # Flip all bits
        
        print(f"\n{hexdump(bytes(modified_ct)[:48])}\n")
        
        # Try to decrypt modified message
        print_attack("Attempting to decrypt modified message...")
        modified_payload = {
            'ciphertext': bytes(modified_ct),
            'tag': encrypted['tag'],
            'nonce': encrypted['nonce']
        }
        
        result = channel.decrypt_message(modified_payload)
        
        if "DECRYPTION FAILED" in result:
            print_success("✓ Modification attack BLOCKED! Authentication tag verification failed")
            print_info(f"Reason: {result}")
        else:
            print_error(f"✗ Modification attack succeeded: {result}")
    
    print()
    press_enter_to_continue()


def demo_eavesdropping_protection():
    """Demonstrate eavesdropping protection via quantum-resistant encryption."""
    print_header("Demonstration 4: Eavesdropping Protection")
    
    print_info("Scenario: Passive eavesdropper captures all network traffic")
    print()
    
    message = "Secret nuclear launch codes: ALPHA-OMEGA-7734"
    
    print_warning(f"Sensitive Message: '{message}'")
    print_info("Alice sends this to Bob over an insecure channel...")
    print()
    
    # Show what eavesdropper captures
    print_attack("EVE (Eavesdropper) captures:")
    
    with oqs.KeyEncapsulation("Kyber768") as kem:
        # Bob's public key (visible)
        pk = kem.generate_keypair()
        print(f"  1. Bob's Public Key ({len(pk)} bytes)")
        print(f"{hexdump(pk[:64], prefix='     ')}")
        print()
        
        # Alice encapsulates (ciphertext visible)
        ct, shared_secret_alice = kem.encap_secret(pk)
        print(f"  2. KEM Ciphertext ({len(ct)} bytes)")
        print(f"{hexdump(ct[:64], prefix='     ')}")
        print()
        
        # Alice encrypts message (ciphertext visible)
        channel_alice = SecureChannel(shared_secret_alice)
        encrypted = channel_alice.encrypt_message(message)
        print(f"  3. AES-GCM Encrypted Message ({len(encrypted['ciphertext'])} bytes)")
        print(f"{hexdump(encrypted['ciphertext'], prefix='     ')}")
        print()
    
    print_info("What Eve CANNOT obtain:")
    print(colored("  ✗ Shared secret (protected by lattice problems)", Colors.FAIL))
    print(colored("  ✗ AES decryption key (derived from shared secret)", Colors.FAIL))
    print(colored("  ✗ Original plaintext message", Colors.FAIL))
    print()
    
    print_success("Even with a quantum computer running Shor's algorithm:")
    print(colored("  • Lattice problems (LWE) have no known quantum speedup", Colors.OKGREEN))
    print(colored("  • Breaking this requires ~2^192 operations (infeasible)", Colors.OKGREEN))
    print()
    
    press_enter_to_continue()


def demo_quantum_threat():
    """Demonstrate the quantum computing threat to classical cryptography."""
    print_header("Demonstration 5: Why Quantum-Resistant Crypto Matters")
    
    print_subheader("Classical Cryptography (RSA-2048)")
    
    print_info("RSA-2048 Security:")
    print("  • Classical Attack: ~2^112 operations (secure)")
    print("  • Quantum Attack (Shor): ~O(n³) ≈ 2^30 operations (BROKEN!)")
    print()
    
    print_warning("Estimated Quantum Requirements to Break RSA-2048:")
    print("  • Logical Qubits: ~4,000")
    print("  • Physical Qubits: ~20,000,000 (with error correction)")
    print("  • Timeline: Potentially 10-20 years")
    print()
    
    print_subheader("Post-Quantum Cryptography")
    
    print_success("CRYSTALS-Kyber Security:")
    print("  • Classical Attack: ~2^192 operations")
    print("  • Quantum Attack: ~2^192 operations (NO SPEEDUP!)")
    print("  • Reason: No efficient quantum algorithm for Module-LWE")
    print()
    
    print_success("Classic McEliece Security:")
    print("  • Classical Attack: ~2^256 operations")
    print("  • Quantum Attack: ~2^256 operations (NO SPEEDUP!)")
    print("  • Reason: Syndrome decoding remains hard for quantum computers")
    print()
    
    press_enter_to_continue()


def main_menu():
    """Display interactive menu."""
    while True:
        clear_screen()
        print_banner()
        
        print(colored("Select a demonstration:", Colors.BOLD))
        print()
        print("  1. Normal Secure Communication (Kyber vs McEliece)")
        print("  2. Replay Attack Prevention")
        print("  3. Message Modification Attack Prevention")
        print("  4. Eavesdropping Protection")
        print("  5. Quantum Threat Analysis")
        print("  6. Run All Demonstrations")
        print("  0. Exit")
        print()
        
        choice = input(colored("Enter choice: ", Colors.OKCYAN))
        
        if choice == '1':
            clear_screen()
            demo_normal_communication()
        elif choice == '2':
            clear_screen()
            demo_replay_attack()
        elif choice == '3':
            clear_screen()
            demo_modification_attack()
        elif choice == '4':
            clear_screen()
            demo_eavesdropping_protection()
        elif choice == '5':
            clear_screen()
            demo_quantum_threat()
        elif choice == '6':
            clear_screen()
            print_banner()
            demo_normal_communication()
            demo_replay_attack()
            demo_modification_attack()
            demo_eavesdropping_protection()
            demo_quantum_threat()
            print_header("All Demonstrations Complete!")
            press_enter_to_continue()
        elif choice == '0':
            print()
            print_success("Thank you for using PQC Secure Communication Demo!")
            print()
            break
        else:
            print_error("Invalid choice. Please try again.")
            time.sleep(1)


if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print()
        print_warning("\nDemo interrupted by user.")
        sys.exit(0)
