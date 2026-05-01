"""Base class for quantum-resistant protocols to eliminate code duplication."""
import oqs
from abc import ABC, abstractmethod
from .secure_channel import SecureChannel
from .utils import print_info, print_success, print_header, hexdump


class BaseProtocol(ABC):
    """Abstract base class for PQC protocols."""
    
    def __init__(self, kem_name: str, display_name: str):
        """
        Initialize protocol.
        
        Args:
            kem_name: OpenQuantumSafe KEM algorithm name
            display_name: Human-readable name for display
        """
        self.kem_name = kem_name
        self.display_name = display_name
        self.metrics = {}
    
    @abstractmethod
    def get_security_level(self) -> str:
        """Return NIST security level."""
        pass
    
    def run_secure_communication(self, secret_message: str, verbose: bool = True) -> dict:
        """
        Execute complete secure communication protocol.
        
        Args:
            secret_message: Message to encrypt
            verbose: Whether to print detailed output
            
        Returns:
            dict containing metrics and results
        """
        if verbose:
            print_header(f"{self.display_name} Secure Communication")
        
        import time
        results = {
            'scheme': self.display_name,
            'message': secret_message,
            'success': False
        }
        
        with oqs.KeyEncapsulation(self.kem_name) as kem:
            # Step 1: Key Generation
            start = time.perf_counter()
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
            keygen_time = (time.perf_counter() - start) * 1000
            
            if verbose:
                print_info(f"Receiver generated {self.kem_name} keypair")
                print(f"    Public Key:  {len(public_key):,} bytes")
                print(f"    Secret Key:  {len(secret_key):,} bytes")
                print(f"    Time:        {keygen_time:.3f} ms\n")
            
            results['pk_size'] = len(public_key)
            results['sk_size'] = len(secret_key)
            results['keygen_time'] = keygen_time
            
            # Step 2: Encapsulation
            start = time.perf_counter()
            ciphertext, shared_secret_sender = kem.encap_secret(public_key)
            encap_time = (time.perf_counter() - start) * 1000
            
            if verbose:
                print_info(f"Sender encapsulated shared secret")
                print(f"    KEM Ciphertext: {len(ciphertext):,} bytes")
                print(f"    Shared Secret:  {len(shared_secret_sender)} bytes")
                print(f"    Time:           {encap_time:.3f} ms")
                if len(ciphertext) <= 1200:  # Only show hex for reasonable sizes
                    print(f"\n{hexdump(ciphertext[:64], prefix='    ')}")
                print()
            
            results['ct_size'] = len(ciphertext)
            results['encap_time'] = encap_time
            
            # Step 3: AES-GCM Encryption
            sender_channel = SecureChannel(shared_secret_sender)
            start = time.perf_counter()
            encrypted_payload = sender_channel.encrypt_message(secret_message)
            aes_enc_time = (time.perf_counter() - start) * 1000
            
            if verbose:
                print_info(f"Sender encrypted message with AES-256-GCM")
                print(f"    Plaintext:  {len(secret_message)} bytes")
                print(f"    Ciphertext: {len(encrypted_payload['ciphertext'])} bytes")
                print(f"    Nonce:      {len(encrypted_payload['nonce'])} bytes")
                print(f"    Auth Tag:   {len(encrypted_payload['tag'])} bytes")
                print(f"    Time:       {aes_enc_time:.3f} ms")
                print(f"\n{hexdump(encrypted_payload['ciphertext'][:48], prefix='    ')}")
                print()
            
            results['aes_ct_size'] = len(encrypted_payload['ciphertext'])
            results['aes_enc_time'] = aes_enc_time
            
            # Step 4: Decapsulation
            start = time.perf_counter()
            shared_secret_receiver = kem.decap_secret(ciphertext)
            decap_time = (time.perf_counter() - start) * 1000
            
            if verbose:
                print_info(f"Receiver decapsulated to recover shared secret")
                print(f"    Time: {decap_time:.3f} ms")
                print(f"    Secrets match: {shared_secret_sender == shared_secret_receiver}\n")
            
            results['decap_time'] = decap_time
            
            # Step 5: AES-GCM Decryption
            receiver_channel = SecureChannel(shared_secret_receiver)
            start = time.perf_counter()
            decrypted_message = receiver_channel.decrypt_message(encrypted_payload)
            aes_dec_time = (time.perf_counter() - start) * 1000
            
            if verbose:
                print_success(f"Receiver decrypted message: '{decrypted_message}'")
                print(f"    Time: {aes_dec_time:.3f} ms")
                print(f"    Message integrity verified ✓")
                print(f"    Timestamp validated ✓\n")
            
            results['aes_dec_time'] = aes_dec_time
            results['decrypted'] = decrypted_message
            results['success'] = (decrypted_message == secret_message)
            results['total_time'] = (keygen_time + encap_time + aes_enc_time + 
                                    decap_time + aes_dec_time)
        
        return results


class KyberProtocol(BaseProtocol):
    """CRYSTALS-Kyber lattice-based protocol."""
    
    def __init__(self):
        super().__init__("Kyber768", "CRYSTALS-Kyber768")
    
    def get_security_level(self) -> str:
        return "NIST Level 3 (≈ AES-192)"


class McElieceProtocol(BaseProtocol):
    """Classic McEliece code-based protocol."""
    
    def __init__(self):
        super().__init__("Classic-McEliece-6960119", "Classic McEliece")
    
    def get_security_level(self) -> str:
        return "NIST Level 5 (≈ AES-256)"
