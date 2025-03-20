"""
Utility functions for JnxBetaSec.
"""

import os
import logging
from typing import Dict, List, Optional, Union
from pathlib import Path
from tqdm import tqdm

from jnxbetasec.core.encryption import Encryption
from jnxbetasec.core.hashing import Hashing

logger = logging.getLogger("jnxbetasec.utils")

class BatchProcessor:
    """
    Batch processing utilities for JnxBetaSec.
    """
    
    def __init__(self, user_id: str = "default_user", organization_id: str = "default"):
        """
        Initialize the batch processor.
        
        Args:
            user_id: User ID for encryption operations
            organization_id: Organization ID for encryption operations
        """
        self.user_id = user_id
        self.organization_id = organization_id
        self.encryption = Encryption(user_id=user_id, organization_id=organization_id)
        self.hashing = Hashing()
    
    def encrypt_directory(self, directory: str, password: str, recursive: bool = False, 
                         content_type: Optional[str] = None) -> List[str]:
        """
        Encrypt all files in a directory.
        
        Args:
            directory: Directory containing files to encrypt
            password: Password for encryption
            recursive: Whether to process subdirectories
            content_type: Content type for all files (optional)
            
        Returns:
            List of paths to encrypted files
        """
        directory = Path(directory)
        if not directory.exists() or not directory.is_dir():
            raise ValueError(f"Invalid directory: {directory}")
        
        encrypted_files = []
        
        if recursive:
            files = list(directory.glob("**/*"))
        else:
            files = list(directory.glob("*"))
        
        files = [f for f in files if f.is_file() and f.suffix.lower() != ".jnx"]
        
        for file_path in tqdm(files, desc="Encrypting files"):
            try:
                encrypted_file = self.encryption.encrypt_file(
                    file_path=str(file_path),
                    password=password,
                    content_type=content_type
                )
                encrypted_files.append(encrypted_file)
            except Exception as e:
                logger.error(f"Failed to encrypt {file_path}: {e}")
        
        return encrypted_files
    
    def decrypt_directory(self, directory: str, password: str, recursive: bool = False,
                         output_dir: Optional[str] = None) -> List[str]:
        """
        Decrypt all .jnx files in a directory.
        
        Args:
            directory: Directory containing files to decrypt
            password: Password for decryption
            recursive: Whether to process subdirectories
            output_dir: Directory to save decrypted files (optional)
            
        Returns:
            List of paths to decrypted files
        """
        directory = Path(directory)
        if not directory.exists() or not directory.is_dir():
            raise ValueError(f"Invalid directory: {directory}")
        
        if output_dir:
            output_path = Path(output_dir)
            output_path.mkdir(exist_ok=True, parents=True)
        else:
            output_path = None
        
        decrypted_files = []
        
        if recursive:
            files = list(directory.glob("**/*.jnx"))
        else:
            files = list(directory.glob("*.jnx"))
        
        for file_path in tqdm(files, desc="Decrypting files"):
            try:
                output_file = None
                if output_path:
                    rel_path = file_path.relative_to(directory)
                    output_file = output_path / rel_path.with_suffix("")
                    output_file.parent.mkdir(exist_ok=True, parents=True)
                
                decrypted_file = self.encryption.decrypt_file(
                    file_path=str(file_path),
                    password=password,
                    output_path=str(output_file) if output_file else None
                )
                decrypted_files.append(decrypted_file)
            except Exception as e:
                logger.error(f"Failed to decrypt {file_path}: {e}")
        
        return decrypted_files
    
    def hash_directory(self, directory: str, algorithm: str = "sha256", 
                      recursive: bool = False) -> Dict[str, str]:
        """
        Generate hashes for all files in a directory.
        
        Args:
            directory: Directory containing files to hash
            algorithm: Hash algorithm to use
            recursive: Whether to process subdirectories
            
        Returns:
            Dictionary mapping file paths to their hashes
        """
        directory = Path(directory)
        if not directory.exists() or not directory.is_dir():
            raise ValueError(f"Invalid directory: {directory}")
        
        file_hashes = {}
        
        if recursive:
            files = list(directory.glob("**/*"))
        else:
            files = list(directory.glob("*"))
        
        files = [f for f in files if f.is_file()]
        
        for file_path in tqdm(files, desc=f"Generating {algorithm} hashes"):
            try:
                file_hash = self.hashing.hash_file(
                    file_path=str(file_path),
                    algorithm=algorithm
                )
                file_hashes[str(file_path)] = file_hash
            except Exception as e:
                logger.error(f"Failed to hash {file_path}: {e}")
        
        return file_hashes

