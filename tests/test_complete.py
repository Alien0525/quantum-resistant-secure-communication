"""
Comprehensive test suite for quantum-resistant cryptography implementation.
"""
import pytest
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.base_protocol import KyberProtocol, McElieceProtocol
from src.secure_channel import SecureChannel
from Crypto.Random import get_random_bytes
import time


class TestInstallation:
    """Test that all required libraries are installed."""
    
    def test_liboqs_import(self):
        """Test liboqs-python is installed."""
        import oqs
        assert oqs.oqs_version() is not None
    
    def test_kyber_available(self):
        """Test Kyber is available in liboqs."""
        import oqs
        kem = oqs.KeyEncapsulation("Kyber768")
        assert kem is not None
        del kem
    
    def test_mceliece_available(self):
        """Test Classic McEliece is available."""
        import oqs
        kem = oqs.KeyEncapsulation("Classic-McEliece-6960119")
        assert kem is not None
        del kem
    
    def test_pycryptodome(self):
        """Test PyCryptodome AES."""
        from Crypto.Cipher import AES
        key = get_random_bytes(32)
        cipher = AES.new(key, AES.MODE_GCM)
        assert cipher is not None


class TestKyberProtocol:
    """Test CRYSTALS-Kyber protocol."""
    
    def test_initialization(self):
        """Test protocol initialization."""
        kyber = KyberProtocol()
        assert kyber.kem_name == "Kyber768"
        assert kyber.display_name == "CRYSTALS-Kyber768"
    
    def test_security_level(self):
        """Test security level reporting."""
        kyber = KyberProtocol()
        assert "NIST Level 3" in kyber.get_security_level()
    
    def test_communication(self):
        """Test end-to-end secure communication."""
        SecureChannel.reset_nonce_cache()
        kyber = KyberProtocol()
        message = "Test message for Kyber"
        
        results = kyber.run_secure_communication(message, verbose=False)
        
        assert results['success'] is True
        assert results['decrypted'] == message
        assert results['scheme'] == "CRYSTALS-Kyber768"
    
    def test_key_sizes(self):
        """Test key sizes are as expected."""
        kyber = KyberProtocol()
        results = kyber.run_secure_communication("test", verbose=False)
        
        # Kyber768 typical sizes
        assert 1100 < results['pk_size'] < 1300  # ~1184 bytes
        assert 2300 < results['sk_size'] < 2500  # ~2400 bytes
        assert 1000 < results['ct_size'] < 1200  # ~1088 bytes
    
    def test_performance(self):
        """Test performance is reasonable."""
        kyber = KyberProtocol()
        results = kyber.run_secure_communication("test", verbose=False)
        
        # Should be very fast
        assert results['total_time'] < 10  # Less than 10ms total


class TestMcElieceProtocol:
    """Test Classic McEliece protocol."""
    
    def test_initialization(self):
        """Test protocol initialization."""
        mceliece = McElieceProtocol()
        assert mceliece.kem_name == "Classic-McEliece-6960119"
        assert mceliece.display_name == "Classic McEliece"
    
    def test_security_level(self):
        """Test security level reporting."""
        mceliece = McElieceProtocol()
        assert "NIST Level 5" in mceliece.get_security_level()
    
    def test_communication(self):
        """Test end-to-end secure communication."""
        SecureChannel.reset_nonce_cache()
        mceliece = McElieceProtocol()
        message = "Test message for McEliece"
        
        results = mceliece.run_secure_communication(message, verbose=False)
        
        assert results['success'] is True
        assert results['decrypted'] == message
        assert results['scheme'] == "Classic McEliece"
    
    def test_key_sizes(self):
        """Test key sizes are as expected."""
        mceliece = McElieceProtocol()
        results = mceliece.run_secure_communication("test", verbose=False)
        
        # McEliece6960119 typical sizes
        assert 1_000_000 < results['pk_size'] < 1_100_000  # ~1MB
        assert 13_000 < results['sk_size'] < 15_000  # ~13KB
        assert 100 < results['ct_size'] < 300  # ~194-226 bytes depending on liboqs version


class TestSecureChannel:
    """Test AES-GCM secure channel."""
    
    def test_encryption_decryption(self):
        """Test basic encryption and decryption."""
        SecureChannel.reset_nonce_cache()
        shared_secret = get_random_bytes(32)
        channel = SecureChannel(shared_secret)
        
        message = "Test message for AES-GCM"
        encrypted = channel.encrypt_message(message)
        decrypted = channel.decrypt_message(encrypted)
        
        assert decrypted == message
    
    def test_encryption_components(self):
        """Test encrypted payload has all components."""
        shared_secret = get_random_bytes(32)
        channel = SecureChannel(shared_secret)
        
        encrypted = channel.encrypt_message("test")
        
        assert 'ciphertext' in encrypted
        assert 'tag' in encrypted
        assert 'nonce' in encrypted
        assert 'timestamp' in encrypted
        
        assert len(encrypted['nonce']) == 12  # GCM nonce
        assert len(encrypted['tag']) == 16    # GCM tag
    
    def test_wrong_key_fails(self):
        """Test that wrong key causes decryption failure."""
        secret1 = get_random_bytes(32)
        secret2 = get_random_bytes(32)
        
        channel1 = SecureChannel(secret1)
        channel2 = SecureChannel(secret2)
        
        encrypted = channel1.encrypt_message("test")
        decrypted = channel2.decrypt_message(encrypted)
        
        assert "DECRYPTION FAILED" in decrypted
    
    def test_tampering_detection(self):
        """Test that modified ciphertext is detected."""
        shared_secret = get_random_bytes(32)
        channel = SecureChannel(shared_secret)
        
        encrypted = channel.encrypt_message("test")
        
        # Tamper with ciphertext
        tampered = bytearray(encrypted['ciphertext'])
        tampered[0] ^= 0xFF
        encrypted['ciphertext'] = bytes(tampered)
        
        decrypted = channel.decrypt_message(encrypted)
        
        assert "DECRYPTION FAILED" in decrypted
    
    def test_replay_protection(self):
        """Test replay attack is detected."""
        SecureChannel.reset_nonce_cache()  # Clean slate
        
        shared_secret = get_random_bytes(32)
        channel = SecureChannel(shared_secret)
        
        encrypted = channel.encrypt_message("test")
        
        # First decryption should succeed
        decrypted1 = channel.decrypt_message(encrypted)
        assert decrypted1 == "test"
        
        # Second decryption with same nonce should fail
        decrypted2 = channel.decrypt_message(encrypted)
        assert "Nonce already used" in decrypted2 or "DECRYPTION FAILED" in decrypted2
    
    def test_timestamp_validation(self):
        """Test old messages are rejected."""
        shared_secret = get_random_bytes(32)
        channel = SecureChannel(shared_secret)
        
        encrypted = channel.encrypt_message("test")
        
        # Message should be valid immediately
        decrypted = channel.decrypt_message(encrypted, max_age_seconds=60)
        assert decrypted == "test"
        
        # Reset nonce cache for second test
        SecureChannel.reset_nonce_cache()
        
        # Simulate old message by modifying timestamp
        import struct
        old_timestamp = struct.pack('>Q', int(time.time()) - 100)
        encrypted['timestamp'] = old_timestamp
        
        decrypted = channel.decrypt_message(encrypted, max_age_seconds=60)
        assert "too old" in decrypted.lower()


class TestComparison:
    """Test comparative aspects of both schemes."""
    
    def test_kyber_faster_than_mceliece(self):
        """Verify Kyber is faster than McEliece."""
        SecureChannel.reset_nonce_cache()
        kyber = KyberProtocol()
        mceliece = McElieceProtocol()
        
        k_results = kyber.run_secure_communication("test", verbose=False)
        m_results = mceliece.run_secure_communication("test", verbose=False)
        
        # Kyber should be significantly faster
        assert k_results['keygen_time'] < m_results['keygen_time']
        assert k_results['total_time'] < m_results['total_time']
    
    def test_kyber_smaller_keys(self):
        """Verify Kyber has smaller keys than McEliece."""
        SecureChannel.reset_nonce_cache()
        kyber = KyberProtocol()
        mceliece = McElieceProtocol()
        
        k_results = kyber.run_secure_communication("test", verbose=False)
        m_results = mceliece.run_secure_communication("test", verbose=False)
        
        # Kyber keys should be much smaller
        assert k_results['pk_size'] < m_results['pk_size']
        assert k_results['sk_size'] < m_results['sk_size']
    
    def test_mceliece_smaller_ciphertext(self):
        """Verify McEliece has smaller ciphertext."""
        SecureChannel.reset_nonce_cache()
        kyber = KyberProtocol()
        mceliece = McElieceProtocol()
        
        k_results = kyber.run_secure_communication("test", verbose=False)
        m_results = mceliece.run_secure_communication("test", verbose=False)
        
        # McEliece ciphertext should be smaller
        assert m_results['ct_size'] < k_results['ct_size']


if __name__ == "__main__":
    # Run tests with verbose output
    pytest.main([__file__, "-v", "--tb=short"])
