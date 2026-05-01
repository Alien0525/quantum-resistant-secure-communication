"""
Enhanced PQC Secure Chat Client with visual ciphertext display.

This client demonstrates real-world quantum-resistant secure communication
with colored output, hex dumps, and attack protection visualization.
"""
import socket
import oqs
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.secure_channel import SecureChannel
from src.utils import (
    print_banner, print_header, print_info, print_success, print_warning,
    print_error, hexdump, colored, Colors, print_attack
)


def run_client():
    """Run the secure chat client with enhanced visualization."""
    print_banner()
    print_header("Quantum-Resistant Secure Chat Client (Bob)")
    
    kem_name = "Kyber768"
    HOST = 'localhost'
    PORT = 9999
    
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    print_info(f"Connecting to server at {HOST}:{PORT}...")
    
    try:
        client.connect((HOST, PORT))
        print_success(f"Connected to server!")
        print()
        
        with oqs.KeyEncapsulation(kem_name) as kem:
            # ===== KEY EXCHANGE PHASE =====
            print_header("Phase 1: Quantum-Resistant Key Exchange")
            
            # 1. Receive public key from server
            print_info("Receiving server's public key...")
            public_key = client.recv(4096)
            print_success(f"Received public key ({len(public_key)} bytes)")
            print(f"\n{hexdump(public_key[:64], prefix='  ')}\n")
            
            # 2. Encapsulate shared secret
            print_info(f"Encapsulating shared secret using {kem_name}...")
            ciphertext, shared_secret = kem.encap_secret(public_key)
            print_success(f"Shared secret encapsulated!")
            print(f"  KEM Ciphertext: {len(ciphertext)} bytes")
            print(f"  Shared Secret:  {len(shared_secret)} bytes")
            print()
            
            # 3. Send ciphertext to server
            print_info("Sending encapsulated secret to server...")
            client.send(ciphertext)
            print(f"\n{hexdump(ciphertext[:64], prefix='  ')}\n")
            
            print_success("🔒 AES-256-GCM Secure Channel Established!")
            print()
            
            channel = SecureChannel(shared_secret)
            
            # ===== SECURE CHAT PHASE =====
            print_header("Phase 2: Encrypted Communication")
            print_info("Type messages to send. Type 'quit' to exit.\n")
            
            msg_count = 0
            
            while True:
                # Send message
                msg = input(colored("You (Bob): ", Colors.OKCYAN))
                
                if msg.lower() == 'quit':
                    print_info("Sending quit signal...")
                
                encrypted = channel.encrypt_message(msg)
                payload = encrypted['nonce'] + encrypted['tag'] + encrypted['ciphertext']
                
                print_info(f"📤 Sending encrypted message #{msg_count + 1}")
                print(colored(f"  Plaintext:  {msg}", Colors.GRAY))
                print(colored(f"  Nonce:      {encrypted['nonce'].hex()[:24]}...", Colors.GRAY))
                print(colored(f"  Auth Tag:   {encrypted['tag'].hex()[:24]}...", Colors.GRAY))
                print(colored(f"  Ciphertext: ({len(encrypted['ciphertext'])} bytes)", Colors.GRAY))
                print(f"\n{hexdump(encrypted['ciphertext'][:64], prefix='    ')}\n")
                
                client.send(payload)
                
                if msg.lower() == 'quit':
                    break
                
                # Receive reply
                enc_data = client.recv(4096)
                if not enc_data:
                    print_warning("Server disconnected.")
                    break
                
                # Parse encrypted payload
                nonce = enc_data[:12]
                tag = enc_data[12:28]
                ct = enc_data[28:]
                
                # Display encrypted message
                print_info(f"📩 Received encrypted reply")
                print(colored(f"  Nonce:      {nonce.hex()[:24]}...", Colors.GRAY))
                print(colored(f"  Auth Tag:   {tag.hex()[:24]}...", Colors.GRAY))
                print(colored(f"  Ciphertext: ({len(ct)} bytes)", Colors.GRAY))
                print(f"\n{hexdump(ct[:64], prefix='    ')}\n")
                
                # Decrypt and verify
                reply = channel.decrypt_message({'nonce': nonce, 'tag': tag, 'ciphertext': ct})
                
                if "DECRYPTION FAILED" in reply:
                    print_attack(f"⚠️  ATTACK DETECTED: {reply}")
                else:
                    print_success(f"✓ Decrypted & Verified")
                    print(colored(f"  Alice: {reply}", Colors.OKGREEN + Colors.BOLD))
                print()
                
                msg_count += 1
                
                if reply.lower() == 'quit':
                    print_warning("Server requested to quit.")
                    break
    
    except ConnectionRefusedError:
        print_error("Could not connect to server. Make sure server is running.")
    except Exception as e:
        print_error(f"Error: {str(e)}")
    finally:
        client.close()
        print()
        print_success("Client shut down gracefully.")
        print()


if __name__ == "__main__":
    try:
        run_client()
    except KeyboardInterrupt:
        print()
        print_warning("\nClient interrupted by user.")
        print()
        sys.exit(0)
