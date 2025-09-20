#!/usr/bin/env python3
"""
Secure Communication Channel
TLS 1.2+ with mTLS and PKI for endpoint-backend communication
"""

import logging
import json
import ssl
import socket
import time
from typing import Dict, Optional, Any
from pathlib import Path
import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import urllib3

# Disable SSL warnings for development
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

class SecureChannel:
    """
    Secure communication channel with TLS 1.2+ and mutual authentication
    
    Provides encrypted, authenticated communication between VPEW-AI components
    using PKI infrastructure and certificate-based authentication
    """
    
    def __init__(self, cert_path: str, key_path: str, ca_cert_path: str):
        """
        Initialize secure channel
        
        Args:
            cert_path: Path to client certificate
            key_path: Path to client private key
            ca_cert_path: Path to CA certificate
        """
        self.cert_path = Path(cert_path)
        self.key_path = Path(key_path)
        self.ca_cert_path = Path(ca_cert_path)
        
        # SSL/TLS configuration
        self.ssl_context = None
        self.session = requests.Session()
        
        # Initialize SSL context
        self._setup_ssl_context()
        
        logger.info("Secure channel initialized")
    
    def _setup_ssl_context(self) -> None:
        """Setup SSL context with proper security settings"""
        try:
            # Create SSL context with TLS 1.2+
            self.ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            
            # Configure security settings
            self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
            self.ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
            
            # Load CA certificate for server verification
            if self.ca_cert_path.exists():
                self.ssl_context.load_verify_locations(str(self.ca_cert_path))
            else:
                logger.warning(f"CA certificate not found: {self.ca_cert_path}")
                # For development - disable certificate verification
                self.ssl_context.check_hostname = False
                self.ssl_context.verify_mode = ssl.CERT_NONE
            
            # Load client certificate and key for mutual authentication
            if self.cert_path.exists() and self.key_path.exists():
                self.ssl_context.load_cert_chain(str(self.cert_path), str(self.key_path))
                logger.info("Client certificate loaded for mTLS")
            else:
                logger.warning("Client certificate/key not found - mTLS disabled")
            
            # Configure cipher suites (prefer strong ciphers)
            self.ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
            
            # Configure session for requests
            self.session.verify = str(self.ca_cert_path) if self.ca_cert_path.exists() else False
            if self.cert_path.exists() and self.key_path.exists():
                self.session.cert = (str(self.cert_path), str(self.key_path))
            
        except Exception as e:
            logger.error(f"Error setting up SSL context: {e}")
            raise
    
    def send(self, url: str, data: Dict, method: str = 'POST', timeout: int = 30) -> Dict:
        """
        Send data securely to backend
        
        Args:
            url: Target URL
            data: Data to send
            method: HTTP method
            timeout: Request timeout in seconds
            
        Returns:
            Response dictionary
        """
        try:
            # Prepare request data
            json_data = json.dumps(data, default=str)
            
            # Add security headers
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'VPEW-AI/1.0',
                'X-VPEW-Version': '0.1.0',
                'X-Request-ID': self._generate_request_id(),
                'X-Timestamp': str(int(time.time()))
            }
            
            # Add HMAC signature for integrity
            signature = self._create_signature(json_data)
            if signature:
                headers['X-Signature'] = signature
            
            # Make request
            if method.upper() == 'POST':
                response = self.session.post(
                    url, 
                    data=json_data,
                    headers=headers,
                    timeout=timeout
                )
            elif method.upper() == 'GET':
                response = self.session.get(
                    url,
                    headers=headers, 
                    timeout=timeout
                )
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            # Check response
            response.raise_for_status()
            
            # Parse response
            try:
                response_data = response.json()
            except json.JSONDecodeError:
                response_data = {"raw_response": response.text}
            
            logger.debug(f"Successfully sent data to {url}")
            return response_data
            
        except requests.exceptions.SSLError as e:
            logger.error(f"SSL error communicating with {url}: {e}")
            return {"error": "SSL_ERROR", "details": str(e)}
        
        except requests.exceptions.Timeout as e:
            logger.error(f"Timeout communicating with {url}: {e}")
            return {"error": "TIMEOUT", "details": str(e)}
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error communicating with {url}: {e}")
            return {"error": "REQUEST_ERROR", "details": str(e)}
        
        except Exception as e:
            logger.error(f"Unexpected error communicating with {url}: {e}")
            return {"error": "UNKNOWN_ERROR", "details": str(e)}
    
    def _generate_request_id(self) -> str:
        """Generate unique request ID"""
        import uuid
        return str(uuid.uuid4())
    
    def _create_signature(self, data: str) -> Optional[str]:
        """
        Create HMAC signature for data integrity
        
        Args:
            data: Data to sign
            
        Returns:
            Base64 encoded signature or None if signing fails
        """
        try:
            import hmac
            import base64
            
            # Use a shared secret or certificate-derived key
            # In production, this would be properly managed
            secret_key = b"vpew-ai-shared-secret-key"
            
            signature = hmac.new(
                secret_key,
                data.encode('utf-8'),
                hashes.SHA256()
            ).digest()
            
            return base64.b64encode(signature).decode('ascii')
            
        except Exception as e:
            logger.debug(f"Error creating signature: {e}")
            return None
    
    def verify_signature(self, data: str, signature: str) -> bool:
        """
        Verify HMAC signature
        
        Args:
            data: Data to verify
            signature: Base64 encoded signature
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            import hmac
            import base64
            
            secret_key = b"vpew-ai-shared-secret-key"
            
            expected_signature = hmac.new(
                secret_key,
                data.encode('utf-8'),
                hashes.SHA256()
            ).digest()
            
            provided_signature = base64.b64decode(signature.encode('ascii'))
            
            return hmac.compare_digest(expected_signature, provided_signature)
            
        except Exception as e:
            logger.debug(f"Error verifying signature: {e}")
            return False
    
    def encrypt_data(self, data: str, recipient_cert_path: str) -> Optional[bytes]:
        """
        Encrypt data using recipient's public key
        
        Args:
            data: Data to encrypt
            recipient_cert_path: Path to recipient's certificate
            
        Returns:
            Encrypted data or None if encryption fails
        """
        try:
            # Load recipient certificate
            with open(recipient_cert_path, 'rb') as f:
                cert_data = f.read()
                cert = x509.load_pem_x509_certificate(cert_data)
            
            # Get public key
            public_key = cert.public_key()
            
            # Encrypt data using RSA-OAEP
            from cryptography.hazmat.primitives.asymmetric import padding
            
            encrypted = public_key.encrypt(
                data.encode('utf-8'),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return encrypted
            
        except Exception as e:
            logger.error(f"Error encrypting data: {e}")
            return None
    
    def decrypt_data(self, encrypted_data: bytes) -> Optional[str]:
        """
        Decrypt data using private key
        
        Args:
            encrypted_data: Encrypted data
            
        Returns:
            Decrypted data or None if decryption fails
        """
        try:
            # Load private key
            with open(self.key_path, 'rb') as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None
                )
            
            # Decrypt data using RSA-OAEP
            from cryptography.hazmat.primitives.asymmetric import padding
            
            decrypted = private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return decrypted.decode('utf-8')
            
        except Exception as e:
            logger.error(f"Error decrypting data: {e}")
            return None
    
    def test_connection(self, url: str) -> bool:
        """
        Test connection to backend
        
        Args:
            url: Backend URL to test
            
        Returns:
            True if connection successful, False otherwise
        """
        try:
            response = self.send(
                url + "/health",
                {"test": True},
                method='GET',
                timeout=10
            )
            
            return "error" not in response
            
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False
    
    def get_connection_info(self) -> Dict:
        """
        Get connection information
        
        Returns:
            Dictionary with connection details
        """
        return {
            "cert_path": str(self.cert_path),
            "key_path": str(self.key_path),
            "ca_cert_path": str(self.ca_cert_path),
            "cert_exists": self.cert_path.exists(),
            "key_exists": self.key_path.exists(),
            "ca_exists": self.ca_cert_path.exists(),
            "mtls_enabled": self.cert_path.exists() and self.key_path.exists(),
            "ssl_version": f"TLS 1.2+"
        }
