"""
Tests for the hashing module.
"""

import os
import tempfile
import unittest
from pathlib import Path

from jnxbetasec.core.hashing import Hashing


class TestHashing(unittest.TestCase):
    """Test cases for the Hashing class."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.TemporaryDirectory()
        
        self.test_file = Path(self.temp_dir.name) / "test_file.txt"
        with open(self.test_file, "w") as f:
            f.write("This is a test file for hashing.")
        
        self.hashing = Hashing()
    
    def tearDown(self):
        """Clean up test environment."""
        self.temp_dir.cleanup()
    
    def test_hash_file(self):
        """Test that a file can be hashed."""
        for algorithm in ["md5", "sha1", "sha256", "sha512"]:
            file_hash = self.hashing.hash_file(
                file_path=str(self.test_file),
                algorithm=algorithm
            )
            
            self.assertIsInstance(file_hash, str)
            self.assertTrue(len(file_hash) > 0)
    
    def test_verify_file(self):
        """Test that a file can be verified against its hash."""
        file_hash = self.hashing.hash_file(
            file_path=str(self.test_file),
            algorithm="sha256"
        )
        
        result = self.hashing.verify_file(
            file_path=str(self.test_file),
            expected_hash=file_hash,
            algorithm="sha256"
        )
        
        self.assertTrue(result)
        
        result = self.hashing.verify_file(
            file_path=str(self.test_file),
            expected_hash="wrong_hash",
            algorithm="sha256"
        )
        
        self.assertFalse(result)
    
    def test_hash_string(self):
        """Test that a string can be hashed."""
        test_string = "This is a test string for hashing."
        
        for algorithm in ["md5", "sha1", "sha256", "sha512"]:
            string_hash = self.hashing.hash_string(
                input_string=test_string,
                algorithm=algorithm
            )
            
            self.assertIsInstance(string_hash, str)
            self.assertTrue(len(string_hash) > 0)
    
    def test_unsupported_algorithm(self):
        """Test that an error is raised for unsupported algorithms."""
        with self.assertRaises(ValueError):
            self.hashing.hash_file(
                file_path=str(self.test_file),
                algorithm="unsupported_algorithm"
            )


if __name__ == "__main__":
    unittest.main()

