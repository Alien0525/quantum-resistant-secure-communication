"""
Enhanced PQC Secure Chat Client with visual ciphertext display.
Full-duplex: Bob can send at any time, not just as turns.
"""
import socket
import oqs
import sys
import os
import threading

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
        print_success("Connected to server!")
        print()

        with oqs.KeyEncapsulation(kem_name) as kem:
            # ===== KEY EXCHANGE PHASE =====
            print_header("Phase 1: Quantum-Resistant Key Exchange")

            print_info("Receiving server's public key...")
            public_key = client.recv(4096)
            print_success(f"Received public key ({len(public_key)} bytes)")
            print(f"\n{hexdump(public_key[:64], prefix='  ')}\n")

            print_info(f"Encapsulating shared secret using {kem_name}...")
            ciphertext, shared_secret = kem.encap_secret(public_key)
            print_success("Shared secret encapsulated!")
            print(f"  KEM Ciphertext: {len(ciphertext)} bytes")
            print(f"  Shared Secret:  {len(shared_secret)} bytes")
            print()

            print_info("Sending encapsulated secret to server...")
            client.send(ciphertext)
            print(f"\n{hexdump(ciphertext[:64], prefix='  ')}\n")

            print_success("🔒 AES-256-GCM Secure Channel Established!")
            print()

            channel = SecureChannel(shared_secret)
            stop_event = threading.Event()

            # ===== SECURE CHAT PHASE =====
            print_header("Phase 2: Encrypted Communication")
            print_info("Type messages to send. Type 'quit' to exit.\n")

            def receive_loop():
                msg_count = 0
                while not stop_event.is_set():
                    try:
                        client.settimeout(1.0)
                        enc_data = client.recv(4096)
                        if not enc_data:
                            print_warning("\nServer disconnected.")
                            stop_event.set()
                            break

                        nonce = enc_data[:12]
                        timestamp = enc_data[12:20]
                        tag = enc_data[20:36]
                        ct = enc_data[36:]

                        print_info(f"\n📩 Received encrypted message #{msg_count + 1}")
                        print(colored(f"  Nonce:      {nonce.hex()[:24]}...", Colors.GRAY))
                        print(colored(f"  Auth Tag:   {tag.hex()[:24]}...", Colors.GRAY))
                        print(colored(f"  Ciphertext: ({len(ct)} bytes)", Colors.GRAY))
                        print(f"\n{hexdump(ct[:64], prefix='    ')}\n")

                        reply = channel.decrypt_message({
                            'nonce': nonce,
                            'tag': tag,
                            'ciphertext': ct,
                            'timestamp': timestamp
                        })

                        if "DECRYPTION FAILED" in reply:
                            print_attack(f"⚠️  ATTACK DETECTED: {reply}")
                        else:
                            print_success("✓ Decrypted & Verified")
                            print(colored(f"  Alice: {reply}", Colors.OKGREEN + Colors.BOLD))
                        print()

                        msg_count += 1

                        if reply.lower() == 'quit':
                            print_warning("Server requested to quit.")
                            stop_event.set()
                            break

                    except socket.timeout:
                        continue
                    except Exception:
                        stop_event.set()
                        break

            recv_thread = threading.Thread(target=receive_loop, daemon=True)
            recv_thread.start()

            while not stop_event.is_set():
                try:
                    msg = input(colored("You (Bob): ", Colors.OKCYAN))
                except EOFError:
                    break

                if stop_event.is_set():
                    break

                encrypted = channel.encrypt_message(msg)
                payload = (
                    encrypted['nonce']
                    + encrypted['timestamp']
                    + encrypted['tag']
                    + encrypted['ciphertext']
                )

                print_info("📤 Sending encrypted message")
                print(colored(f"  Plaintext:  {msg}", Colors.GRAY))
                print(colored(f"  Nonce:      {encrypted['nonce'].hex()[:24]}...", Colors.GRAY))
                print(colored(f"  Auth Tag:   {encrypted['tag'].hex()[:24]}...", Colors.GRAY))
                print(colored(f"  Ciphertext: ({len(encrypted['ciphertext'])} bytes)", Colors.GRAY))
                print(f"\n{hexdump(encrypted['ciphertext'][:64], prefix='    ')}\n")

                client.send(payload)

                if msg.lower() == 'quit':
                    stop_event.set()
                    break

            recv_thread.join(timeout=2)

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