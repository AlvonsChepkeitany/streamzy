"""
Encryption utilities for Streamzy Chat Platform
Uses Fernet symmetric encryption for messages
"""
import os
import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import logging

logger = logging.getLogger(__name__)


class MessageEncryption:
    """Handle message encryption and decryption using Fernet"""
    
    def __init__(self, key=None):
        """
        Initialize encryption with key from environment or generate new one
        
        Args:
            key: Base64 encoded Fernet key or None to use env variable
        """
        if key:
            self._key = key.encode() if isinstance(key, str) else key
        else:
            self._key = self._get_or_generate_key()
        
        self._fernet = Fernet(self._key)
    
    def _get_or_generate_key(self):
        """Get key from environment or generate new one"""
        env_key = os.environ.get('ENCRYPTION_KEY')
        
        if env_key:
            return env_key.encode()
        
        # Generate new key if not set (for development)
        logger.warning("No ENCRYPTION_KEY found in environment. Generating temporary key.")
        return Fernet.generate_key()
    
    @staticmethod
    def generate_key():
        """Generate a new Fernet key"""
        return Fernet.generate_key().decode()
    
    @staticmethod
    def derive_key_from_password(password, salt=None):
        """
        Derive a Fernet key from a password using PBKDF2
        
        Args:
            password: Password string
            salt: Salt bytes or None to generate new
            
        Returns:
            tuple: (key, salt)
        """
        if salt is None:
            salt = os.urandom(16)
        elif isinstance(salt, str):
            salt = base64.b64decode(salt)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key.decode(), base64.b64encode(salt).decode()
    
    def encrypt(self, plaintext):
        """
        Encrypt a message
        
        Args:
            plaintext: String message to encrypt
            
        Returns:
            bytes: Encrypted message
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        try:
            encrypted = self._fernet.encrypt(plaintext)
            return encrypted
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            raise
    
    def decrypt(self, ciphertext):
        """
        Decrypt a message
        
        Args:
            ciphertext: Encrypted bytes
            
        Returns:
            str: Decrypted message
        """
        try:
            decrypted = self._fernet.decrypt(ciphertext)
            return decrypted.decode('utf-8')
        except InvalidToken:
            logger.error("Invalid token - message may be corrupted or key mismatch")
            return "[Message could not be decrypted]"
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return "[Decryption error]"
    
    def encrypt_for_storage(self, plaintext):
        """
        Encrypt message and return base64 encoded string for JSON storage
        
        Args:
            plaintext: String message
            
        Returns:
            str: Base64 encoded encrypted message
        """
        encrypted = self.encrypt(plaintext)
        return base64.b64encode(encrypted).decode('utf-8')
    
    def decrypt_from_storage(self, stored_value):
        """
        Decrypt base64 encoded encrypted message
        
        Args:
            stored_value: Base64 encoded encrypted message
            
        Returns:
            str: Decrypted message
        """
        try:
            ciphertext = base64.b64decode(stored_value)
            return self.decrypt(ciphertext)
        except Exception as e:
            logger.error(f"Error decoding stored message: {e}")
            return "[Message could not be decoded]"


class HashUtils:
    """Utility functions for hashing"""
    
    @staticmethod
    def hash_email(email):
        """
        Create a hash of email for comparison without storing plain email
        
        Args:
            email: Email address
            
        Returns:
            str: Hex digest of hashed email
        """
        normalized = email.lower().strip()
        return hashlib.sha256(normalized.encode()).hexdigest()
    
    @staticmethod
    def hash_ip(ip_address):
        """
        Create a hash of IP address for privacy
        
        Args:
            ip_address: IP address string
            
        Returns:
            str: Hex digest of hashed IP
        """
        return hashlib.sha256(ip_address.encode()).hexdigest()[:16]


# Singleton instance for the application
_encryption_instance = None


def get_encryption():
    """Get or create the encryption instance"""
    global _encryption_instance
    if _encryption_instance is None:
        _encryption_instance = MessageEncryption()
    return _encryption_instance


def encrypt_message(plaintext):
    """Convenience function to encrypt a message"""
    return get_encryption().encrypt(plaintext)


def decrypt_message(ciphertext):
    """Convenience function to decrypt a message"""
    return get_encryption().decrypt(ciphertext)
