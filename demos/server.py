import socket
import oqs
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.secure_channel import SecureChannel

def run_server():
    print("--- PQC Secure Chat Server (Alice) ---")
    kem_name = "Kyber768"
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 9999))
    server.listen(1)
    print("Waiting for connection on port 9999...")
    
    client, addr = server.accept()
    print(f"Connected to {addr}!")

    with oqs.KeyEncapsulation(kem_name) as kem:
        # 1. Generate PK/SK
        print("[*] Generating Kyber768 Keys...")
        public_key = kem.generate_keypair()
        
        # 2. Send PK to client
        client.send(public_key)
        
        # 3. Receive Ciphertext from client
        print("[*] Waiting for encapsulated secret from client...")
        ciphertext = client.recv(4096)
        
        # 4. Decap to get shared secret
        shared_secret = kem.decap_secret(ciphertext)
        print("[+] Key exchange successful! AES-256-GCM Secure Channel established.\n")
        
        channel = SecureChannel(shared_secret)
        
        # Chat loop
        while True:
            # Receive
            enc_data = client.recv(4096)
            if not enc_data: break
            
            # Need to slice out the nonce (12 bytes), tag (16 bytes), and ciphertext
            nonce = enc_data[:12]
            tag = enc_data[12:28]
            ct = enc_data[28:]
            msg = channel.decrypt_message({'nonce': nonce, 'tag': tag, 'ciphertext': ct})
            print(f"Bob: {msg}")
            
            # Send
            reply = input("You: ")
            encrypted = channel.encrypt_message(reply)
            client.send(encrypted['nonce'] + encrypted['tag'] + encrypted['ciphertext'])

if __name__ == "__main__":
    run_server()