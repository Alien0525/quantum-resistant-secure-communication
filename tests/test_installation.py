"""Test that all required libraries are properly installed."""
import pytest

def test_liboqs_import():
    """Test liboqs-python is installed."""
    import oqs
    assert oqs.oqs_version() is not None

def test_kyber_available():
    """Test Kyber is available in liboqs."""
    import oqs
    kem = oqs.KeyEncapsulation("Kyber768")
    assert kem is not None

def test_mceliece_available():
    """Test Classic McEliece is available."""
    import oqs
    kem = oqs.KeyEncapsulation("Classic-McEliece-6960119")
    assert kem is not None

def test_pycryptodome():
    """Test PyCryptodome AES."""
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    
    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_GCM)
    assert cipher is not None

def test_hmac():
    """Test HMAC functionality."""
    import hmac
    import hashlib
    
    h = hmac.new(b'key', b'message', hashlib.sha256)
    assert len(h.digest()) == 32

if __name__ == "__main__":
    pytest.main([__file__, "-v"])