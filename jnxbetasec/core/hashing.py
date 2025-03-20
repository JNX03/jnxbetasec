"""
Hashing module for JnxBetaSec.
"""

import os
import hashlib
import logging
from typing import Dict, Optional
from pathlib import Path

logger = logging.getLogger("jnxbetasec.hashing")

class Hashing:
    """
    JnxBetaSec Hashing System
    
    Provides secure file hashing and verification capabilities.
    """
    
    SUPPORTED_ALGORITHMS = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512,
        "blake2b": hashlib.blake2b,
        "blake2s": hashlib.blake2s,
    }
    
    def __init__(self):
        """Initialize the JnxBetaSec hashing system."""
        pass
    
    def hash_file(self, file_path: str, algorithm: str = "sha256", chunk_size: int = 8192) -> str:
        """
        Generate a hash for a file.
        
        Args:
            file_path: Path to the file
            algorithm: Hash algorithm to use
            chunk_size: Size of chunks to read from file
            
        Returns:
            Hexadecimal hash string
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        if algorithm.lower() not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: {algorithm}. Supported algorithms: {', '.join(self.SUPPORTED_ALGORITHMS.keys())}")
        
        hash_func = self.SUPPORTED_ALGORITHMS[algorithm.lower()]()
        
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                hash_func.update(chunk)
        
        return hash_func.hexdigest()
    
    def verify_file(self, file_path: str, expected_hash: str, algorithm: str = "sha256") -> bool:
        """
        Verify a file against an expected hash.
        
        Args:
            file_path: Path to the file
            expected_hash: Expected hash value
            algorithm: Hash algorithm to use
            
        Returns:
            True if the hash matches, False otherwise
        """
        actual_hash = self.hash_file(file_path, algorithm)
        return actual_hash.lower() == expected_hash.lower()
    
    def hash_string(self, input_string: str, algorithm: str = "sha256") -> str:
        """
        Generate a hash for a string.
        
        Args:
            input_string: String to hash
            algorithm: Hash algorithm to use
            
        Returns:
            Hexadecimal hash string
        """
        if algorithm.lower() not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: {algorithm}. Supported algorithms: {', '.join(self.SUPPORTED_ALGORITHMS.keys())}")
        
        hash_func = self.SUPPORTED_ALGORITHMS[algorithm.lower()]()
        hash_func.update(input_string.encode('utf-8'))
        
        return hash_func.hexdigest()

