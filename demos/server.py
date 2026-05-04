"""
Enhanced PQC Secure Chat Server with visual ciphertext display.

This server demonstrates real-world quantum-resistant secure communication
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


def run_server():
    """Run the secure chat server with enhanced visualization."""
    print_banner()
    print_header("Quantum-Resistant Secure Chat Server (Alice)")
    
    kem_name = "Kyber768"
    HOST = 'localhost'
    PORT = 9999
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)
    
    print_info(f"Server listening on {HOST}:{PORT}")
    print_warning("Waiting for client connection...")
    print()
    
    client, addr = server.accept()
    print_success(f"Client connected from {addr[0]}:{addr[1]}")
    print()
    
    try:
        with oqs.KeyEncapsulation(kem_name) as kem:
            # ===== KEY EXCHANGE PHASE =====
            print_header("Phase 1: Quantum-Resistant Key Exchange")
            
            # 1. Generate keypair
            print_info(f"Generating {kem_name} keypair...")
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
            
            print_success(f"Keys generated!")
            print(f"  Public Key: {len(public_key):,} bytes")
            print(f"  Secret Key: {len(secret_key):,} bytes")
            print()
            
            # 2. Send public key to client
            print_info("Sending public key to client...")
            client.send(public_key)
            print(f"\n{hexdump(public_key[:64], prefix='  ')}\n")
            
            # 3. Receive encapsulated secret from client
            print_info("Waiting for encapsulated secret from client...")
            ciphertext = client.recv(4096)
            print_success(f"Received KEM ciphertext ({len(ciphertext)} bytes)")
            print(f"\n{hexdump(ciphertext[:64], prefix='  ')}\n")
            
            # 4. Decapsulate to derive shared secret
            print_info("Decapsulating to derive shared secret...")
            shared_secret = kem.decap_secret(ciphertext)
            print_success(f"Shared secret established! ({len(shared_secret)} bytes)")
            print(f"\n{hexdump(shared_secret[:32], prefix='  ')}\n")
            
            print_success("🔒 AES-256-GCM Secure Channel Established!")
            print()
            
            channel = SecureChannel(shared_secret)
            
            # ===== SECURE CHAT PHASE =====
            print_header("Phase 2: Encrypted Communication")
            print_info("Type messages to send. Type 'quit' to exit.\n")
            
            msg_count = 0
            
            while True:
                # Receive encrypted message
                enc_data = client.recv(4096)
                if not enc_data:
                    print_warning("Client disconnected.")
                    break
                
                # Parse encrypted payload: nonce(12) + timestamp(8) + tag(16) + ciphertext
                nonce = enc_data[:12]
                timestamp = enc_data[12:20]
                tag = enc_data[20:36]
                ct = enc_data[36:]
                
                # Display encrypted message
                print_info(f"📩 Received encrypted message #{msg_count + 1}")
                print(colored(f"  Nonce:      {nonce.hex()[:24]}...", Colors.GRAY))
                print(colored(f"  Auth Tag:   {tag.hex()[:24]}...", Colors.GRAY))
                print(colored(f"  Ciphertext: ({len(ct)} bytes)", Colors.GRAY))
                print(f"\n{hexdump(ct[:64], prefix='    ')}\n")
                
                # Decrypt and verify
                msg = channel.decrypt_message({'nonce': nonce, 'tag': tag, 'ciphertext': ct, 'timestamp': timestamp})
                
                if "DECRYPTION FAILED" in msg:
                    print_attack(f"⚠️  ATTACK DETECTED: {msg}")
                else:
                    print_success(f"✓ Decrypted & Verified")
                    print(colored(f"  Bob: {msg}", Colors.OKGREEN + Colors.BOLD))
                print()
                
                msg_count += 1
                
                if msg.lower() == 'quit':
                    print_warning("Client requested to quit.")
                    break
                
                # Send reply
                reply = input(colored("You (Alice): ", Colors.OKCYAN))
                
                if reply.lower() == 'quit':
                    print_info("Sending quit signal...")
                
                encrypted = channel.encrypt_message(reply)
                payload = encrypted['nonce'] + encrypted['timestamp'] + encrypted['tag'] + encrypted['ciphertext']
                
                print_info(f"📤 Sending encrypted reply")
                print(colored(f"  Plaintext:  {reply}", Colors.GRAY))
                print(colored(f"  Ciphertext: ({len(encrypted['ciphertext'])} bytes)", Colors.GRAY))
                print(f"\n{hexdump(encrypted['ciphertext'][:64], prefix='    ')}\n")
                
                client.send(payload)
                
                if reply.lower() == 'quit':
                    break
    
    except Exception as e:
        print_error(f"Error: {str(e)}")
    finally:
        client.close()
        server.close()
        print()
        print_success("Server shut down gracefully.")
        print()


if __name__ == "__main__":
    try:
        run_server()
    except KeyboardInterrupt:
        print()
        print_warning("\nServer interrupted by user.")
        print()
        sys.exit(0)