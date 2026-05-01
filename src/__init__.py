"""
Quantum-Resistant Secure Communication Library.

This package provides post-quantum cryptographic protocols based on
CRYSTALS-Kyber (lattice-based) and Classic McEliece (code-based).
"""
from .base_protocol import KyberProtocol, McElieceProtocol
from .secure_channel import SecureChannel

__version__ = '1.0.0'
__all__ = ['KyberProtocol', 'McElieceProtocol', 'SecureChannel']
