"""
VPEW-AI Communication Module
Secure communication with TLS/mTLS and PKI
"""

from .secure_channel import SecureChannel
from .pki_manager import PKIManager

__all__ = [
    "SecureChannel",
    "PKIManager"
]
