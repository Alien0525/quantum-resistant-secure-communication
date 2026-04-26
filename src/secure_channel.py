import time
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class SecureChannel:
    def __init__(self, shared_secret):
        # Use the first 32 bytes of the PQ shared secret for AES-256
        self.key = shared_secret[:32] 
        self.seen_nonces = set()

    def encrypt_message(self, plaintext_msg):
        """Encrypts a message with timestamp and nonce to prevent replay/modification/eavesdropping."""
        # 1. Replay Protection: Generate timestamp and nonce
        timestamp = str(int(time.time())).encode('utf-8')
        nonce = os.urandom(12)
        
        # Combine timestamp with message
        payload = timestamp + b"||" + plaintext_msg.encode('utf-8')
        
        # 2 & 3. Eavesdropping & Modification Protection: AES-GCM
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(payload)
        
        return {
            'ciphertext': ciphertext,
            'tag': tag,
            'nonce': nonce
        }

    def decrypt_message(self, encrypted_bundle):
        """Decrypts and verifies message integrity and freshness."""
        try:
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=encrypted_bundle['nonce'])
            # Verify tag (Modification protection)
            decrypted_payload = cipher.decrypt_and_verify(
                encrypted_bundle['ciphertext'], 
                encrypted_bundle['tag']
            )
            
            # Replay protection: Check timestamp
            timestamp_bytes, msg = decrypted_payload.split(b"||", 1)
            msg_time = int(timestamp_bytes.decode('utf-8'))
            current_time = int(time.time())
            
            if current_time - msg_time > 60: # 60 second window
                raise ValueError("Message rejected: Timestamp too old (Possible Replay Attack)")
                
            if encrypted_bundle['nonce'] in self.seen_nonces:
                raise ValueError("Message rejected: Nonce already used (Replay Attack)")
                
            self.seen_nonces.add(encrypted_bundle['nonce'])
            
            return msg.decode('utf-8')
            
        except ValueError as e:
            return f"DECRYPTION FAILED: {str(e)}"