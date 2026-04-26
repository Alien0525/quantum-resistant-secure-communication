import socket
import oqs
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.secure_channel import SecureChannel

def run_client():
    print("--- PQC Secure Chat Client (Bob) ---")
    kem_name = "Kyber768"
    
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('localhost', 9999))
    print("Connected to server!")

    with oqs.KeyEncapsulation(kem_name) as kem:
        # 1. Receive PK from server
        public_key = client.recv(4096)
        print(f"[*] Received Kyber768 Public Key ({len(public_key)} bytes)")
        
        # 2. Encap secret
        ciphertext, shared_secret = kem.encap_secret(public_key)
        
        # 3. Send ciphertext back
        client.send(ciphertext)
        print("[+] Key exchange successful! AES-256-GCM Secure Channel established.\n")
        
        channel = SecureChannel(shared_secret)
        
        # Chat loop
        while True:
            # Send
            msg = input("You: ")
            encrypted = channel.encrypt_message(msg)
            client.send(encrypted['nonce'] + encrypted['tag'] + encrypted['ciphertext'])
            
            # Receive
            enc_data = client.recv(4096)
            if not enc_data: break
            
            nonce = enc_data[:12]
            tag = enc_data[12:28]
            ct = enc_data[28:]
            reply = channel.decrypt_message({'nonce': nonce, 'tag': tag, 'ciphertext': ct})
            print(f"Alice: {reply}")

if __name__ == "__main__":
    run_client()