"""
Secure communication channel using AES-256-GCM with replay protection.

This module implements authenticated encryption with:
- AES-256-GCM for confidentiality and integrity
- Timestamp-based replay attack detection
- Nonce tracking for duplicate detection
"""
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
import time
import struct


class SecureChannel:
    """Secure communication channel with AES-256-GCM."""
    
    # Class-level nonce tracking for replay detection
    _used_nonces = set()
    _max_nonce_cache = 10000  # Limit memory usage
    
    def __init__(self, shared_secret: bytes):
        """
        Initialize secure channel from shared secret.
        
        Args:
            shared_secret: Shared secret from KEM
        """
        # Derive 256-bit AES key from shared secret using HKDF
        self.key = HKDF(
            master=shared_secret,
            key_len=32,  # 256 bits
            salt=b'quantum-resistant-aes',
            hashmod=SHA256,
            context=b'secure-channel-v1'
        )
    
    def encrypt_message(self, plaintext: str) -> dict:
        """
        Encrypt message with AES-256-GCM.
        
        Args:
            plaintext: Message to encrypt
            
        Returns:
            dict with 'ciphertext', 'tag', 'nonce', 'timestamp'
        """
        # Generate random nonce (96 bits recommended for GCM)
        nonce = get_random_bytes(12)
        
        # Add timestamp for replay protection (8 bytes)
        timestamp = struct.pack('>Q', int(time.time()))
        
        # Create cipher
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        
        # Add timestamp as additional authenticated data
        cipher.update(timestamp)
        
        # Encrypt and get authentication tag
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
        
        return {
            'ciphertext': ciphertext,
            'tag': tag,
            'nonce': nonce,
            'timestamp': timestamp
        }
    
    def decrypt_message(self, payload: dict, max_age_seconds: int = 60) -> str:
        """
        Decrypt and verify message.
        
        Args:
            payload: Dict with 'ciphertext', 'tag', 'nonce', optionally 'timestamp'
            max_age_seconds: Maximum age for timestamp validation
            
        Returns:
            Decrypted message or error string
        """
        try:
            ciphertext = payload['ciphertext']
            tag = payload['tag']
            nonce = payload['nonce']
            
            # Check for nonce reuse (replay attack)
            nonce_id = nonce.hex()
            if nonce_id in SecureChannel._used_nonces:
                return "DECRYPTION FAILED: Nonce already used - possible replay attack!"
            
            # Validate timestamp if provided
            if 'timestamp' in payload:
                timestamp_bytes = payload['timestamp']
                timestamp = struct.unpack('>Q', timestamp_bytes)[0]
                current_time = int(time.time())
                age = current_time - timestamp
                
                if age > max_age_seconds:
                    return f"DECRYPTION FAILED: Message too old ({age}s > {max_age_seconds}s limit)"
                
                if age < -5:  # Allow 5 second clock skew
                    return "DECRYPTION FAILED: Message timestamp is in the future!"
            
            # Create cipher for decryption
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            
            # Add timestamp as AAD if present
            if 'timestamp' in payload:
                cipher.update(payload['timestamp'])
            
            # Decrypt and verify
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            
            # Mark nonce as used
            SecureChannel._used_nonces.add(nonce_id)
            
            return plaintext.decode('utf-8')
            
        except ValueError as e:
            # Authentication failed
            return f"DECRYPTION FAILED: Message authentication failed - possible tampering! ({str(e)})"
        except Exception as e:
            return f"DECRYPTION FAILED: {str(e)}"
    
    @classmethod
    def reset_nonce_cache(cls):
        """Reset nonce cache (useful for testing)."""
        cls._used_nonces.clear()
