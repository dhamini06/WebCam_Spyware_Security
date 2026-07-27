"""
Crypto Manager for Webcam Spyware Security
Handles encryption and decryption of sensitive data using Fernet
"""

import os
import json
from typing import Optional, Dict, Any
from cryptography.fernet import Fernet
import logging

logger = logging.getLogger(__name__)


class CryptoManager:
    """Manages encryption and decryption operations"""
    
    def __init__(self, key_path: str = None):
        """
        Initialize crypto manager
        
        Args:
            key_path: Path to encryption key file. If not exists, creates new key.
        """
        if key_path is None:
            key_path = os.path.join(os.path.dirname(__file__), 'database', '.encryption_key')
        
        self.key_path = key_path
        self._ensure_key_exists()
        self.cipher = self._load_cipher()
    
    def _ensure_key_exists(self):
        """Ensure encryption key exists, create if not"""
        if not os.path.exists(self.key_path):
            # Create new key
            key = Fernet.generate_key()
            key_dir = os.path.dirname(self.key_path)
            if key_dir and not os.path.exists(key_dir):
                os.makedirs(key_dir, exist_ok=True)
            
            # Save key with restricted permissions
            with open(self.key_path, 'wb') as f:
                f.write(key)
            
            # Set file permissions (Windows)
            os.chmod(self.key_path, 0o600)
            logger.info("New encryption key generated")
    
    def _load_cipher(self) -> Fernet:
        """Load cipher from key file"""
        try:
            with open(self.key_path, 'rb') as f:
                key = f.read()
            return Fernet(key)
        except Exception as e:
            logger.error(f"Failed to load cipher: {e}")
            raise
    
    def encrypt_string(self, plaintext: str) -> str:
        """
        Encrypt a string
        
        Args:
            plaintext: String to encrypt
            
        Returns:
            Encrypted string (base64 encoded)
        """
        try:
            encrypted = self.cipher.encrypt(plaintext.encode())
            return encrypted.decode()
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise
    
    def decrypt_string(self, ciphertext: str) -> str:
        """
        Decrypt a string
        
        Args:
            ciphertext: Encrypted string (base64 encoded)
            
        Returns:
            Decrypted plaintext string
        """
        try:
            decrypted = self.cipher.decrypt(ciphertext.encode())
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise
    
    def encrypt_dict(self, data: Dict[str, Any]) -> str:
        """
        Encrypt a dictionary (converted to JSON)
        
        Args:
            data: Dictionary to encrypt
            
        Returns:
            Encrypted JSON string
        """
        try:
            json_str = json.dumps(data)
            return self.encrypt_string(json_str)
        except Exception as e:
            logger.error(f"Dict encryption failed: {e}")
            raise
    
    def decrypt_dict(self, ciphertext: str) -> Dict[str, Any]:
        """
        Decrypt a dictionary
        
        Args:
            ciphertext: Encrypted JSON string
            
        Returns:
            Decrypted dictionary
        """
        try:
            json_str = self.decrypt_string(ciphertext)
            return json.loads(json_str)
        except Exception as e:
            logger.error(f"Dict decryption failed: {e}")
            raise
    
    def encrypt_file(self, file_path: str, output_path: str = None) -> str:
        """
        Encrypt a file
        
        Args:
            file_path: Path to file to encrypt
            output_path: Path to save encrypted file. Defaults to original + '.enc'
            
        Returns:
            Path to encrypted file
        """
        if output_path is None:
            output_path = f"{file_path}.enc"
        
        try:
            with open(file_path, 'rb') as f:
                plaintext = f.read()
            
            encrypted = self.cipher.encrypt(plaintext)
            
            with open(output_path, 'wb') as f:
                f.write(encrypted)
            
            logger.info(f"File encrypted: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"File encryption failed: {e}")
            raise
    
    def decrypt_file(self, encrypted_file_path: str, output_path: str = None) -> str:
        """
        Decrypt a file
        
        Args:
            encrypted_file_path: Path to encrypted file
            output_path: Path to save decrypted file. Defaults to removing '.enc'
            
        Returns:
            Path to decrypted file
        """
        if output_path is None:
            if encrypted_file_path.endswith('.enc'):
                output_path = encrypted_file_path[:-4]
            else:
                output_path = f"{encrypted_file_path}.dec"
        
        try:
            with open(encrypted_file_path, 'rb') as f:
                ciphertext = f.read()
            
            plaintext = self.cipher.decrypt(ciphertext)
            
            with open(output_path, 'wb') as f:
                f.write(plaintext)
            
            logger.info(f"File decrypted: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"File decryption failed: {e}")
            raise
    
    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash a password using bcrypt
        
        Args:
            password: Password to hash
            
        Returns:
            Hashed password
        """
        try:
            import bcrypt
            salt = bcrypt.gensalt(rounds=12)
            hashed = bcrypt.hashpw(password.encode(), salt)
            return hashed.decode()
        except Exception as e:
            logger.error(f"Password hashing failed: {e}")
            raise
    
    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """
        Verify a password against its hash
        
        Args:
            password: Plain password to verify
            hashed: Hashed password to check against
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            import bcrypt
            return bcrypt.checkpw(password.encode(), hashed.encode())
        except Exception as e:
            logger.error(f"Password verification failed: {e}")
            return False
    
    def rotate_key(self, new_key_path: str = None) -> str:
        """
        Rotate encryption key (create new key and re-encrypt)
        
        Args:
            new_key_path: Path for new key file
            
        Returns:
            Path to new key file
        """
        if new_key_path is None:
            new_key_path = f"{self.key_path}.new"
        
        try:
            # Generate new key
            new_key = Fernet.generate_key()
            with open(new_key_path, 'wb') as f:
                f.write(new_key)
            os.chmod(new_key_path, 0o600)
            
            logger.info(f"New key generated: {new_key_path}")
            logger.warning("Manual key rotation required - re-encrypt all data with new key")
            return new_key_path
        except Exception as e:
            logger.error(f"Key rotation failed: {e}")
            raise


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    
    # Test encryption
    crypto = CryptoManager()
    
    # Test string encryption
    plaintext = "Sensitive data here"
    encrypted = crypto.encrypt_string(plaintext)
    decrypted = crypto.decrypt_string(encrypted)
    print(f"Original: {plaintext}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
    
    # Test password hashing
    password = "SecurePassword123"
    hashed = CryptoManager.hash_password(password)
    verified = CryptoManager.verify_password(password, hashed)
    print(f"\nPassword: {password}")
    print(f"Hashed: {hashed}")
    print(f"Verified: {verified}")
