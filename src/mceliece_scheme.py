import oqs
from .secure_channel import SecureChannel

class McElieceProtocol:
    def __init__(self):
        self.kem_name = "Classic-McEliece-6960119"

    def run_secure_communication(self, secret_message):
        print(f"--- Starting {self.kem_name} Secure Communication ---")
        
        with oqs.KeyEncapsulation(self.kem_name) as kem:
            # 1. Receiver generates keys
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
            print(f"[+] Receiver generated keys. Public Key size: {len(public_key)} bytes")

            # 2. Sender generates a shared secret and encapsulates it
            ciphertext, shared_secret_sender = kem.encap_secret(public_key)
            print(f"[+] Sender encapsulated shared secret. Ciphertext size: {len(ciphertext)} bytes")

            # 3. Sender encrypts the actual message using the shared secret
            sender_channel = SecureChannel(shared_secret_sender)
            encrypted_payload = sender_channel.encrypt_message(secret_message)
            print(f"[+] Sender encrypted message using AES-256-GCM (Message size: {len(encrypted_payload['ciphertext'])} bytes)")

            # 4. Receiver decapsulates to get the shared secret
            shared_secret_receiver = kem.decap_secret(ciphertext)

            # 5. Receiver decrypts the message
            receiver_channel = SecureChannel(shared_secret_receiver)
            decrypted_message = receiver_channel.decrypt_message(encrypted_payload)
            print(f"[+] Receiver successfully decrypted message: '{decrypted_message}'\n")
            
            return decrypted_message