"""
Tests for the encryption module.
"""

import os
import tempfile
import unittest
from pathlib import Path

from jnxbetasec.core.encryption import Encryption


class TestEncryption(unittest.TestCase):
    """Test cases for the Encryption class."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.key_dir = Path(self.temp_dir.name) / "keys"
        self.key_dir.mkdir(exist_ok=True)
        
        self.test_file = Path(self.temp_dir.name) / "test_file.txt"
        with open(self.test_file, "w") as f:
            f.write("This is a test file for encryption.")
        
        self.user_id = "test_user"
        self.password = "test_password"
        
        self.encryption = Encryption(
            user_id=self.user_id,
            key_dir=str(self.key_dir)
        )
    
    def tearDown(self):
        """Clean up test environment."""
        self.temp_dir.cleanup()
    
    def test_encrypt_decrypt_cycle(self):
        """Test that a file can be encrypted and then decrypted."""
        encrypted_file = self.encryption.encrypt_file(
            file_path=str(self.test_file),
            password=self.password
        )
        
        self.assertTrue(Path(encrypted_file).exists())
        self.assertEqual(Path(encrypted_file).suffix, ".jnx")
        
        decrypted_file = self.encryption.decrypt_file(
            file_path=encrypted_file,
            password=self.password
        )
        
        self.assertTrue(Path(decrypted_file).exists())
        
        with open(self.test_file, "r") as f:
            original_content = f.read()
        
        with open(decrypted_file, "r") as f:
            decrypted_content = f.read()
        
        self.assertEqual(original_content, decrypted_content)
    
    def test_wrong_password(self):
        """Test that decryption fails with the wrong password."""
        encrypted_file = self.encryption.encrypt_file(
            file_path=str(self.test_file),
            password=self.password
        )
        
        with self.assertRaises(ValueError):
            self.encryption.decrypt_file(
                file_path=encrypted_file,
                password="wrong_password"
            )
    
    def test_file_not_found(self):
        """Test that an error is raised when the file doesn't exist."""
        with self.assertRaises(FileNotFoundError):
            self.encryption.encrypt_file(
                file_path="nonexistent_file.txt",
                password=self.password
            )


if __name__ == "__main__":
    unittest.main()

