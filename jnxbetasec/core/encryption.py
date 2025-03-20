"""
Encryption module for JnxBetaSec.
"""

import os
import json
import base64
import hashlib
import secrets
import logging
import datetime
from typing import Dict, Any, Union, List, Tuple, Optional
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

logger = logging.getLogger("jnxbetasec.encryption")


class Encryption:
    """
    JnxBetaSec Encryption System
    
    A multi-layered encryption system designed for secure file protection.
    """
    
    VERSION = "1.0.0"
    
    FILE_SIGNATURE = b"JNXBETASEC"
    
    ITERATIONS = 600000
    KEY_LENGTH = 32  # 256 bits
    
    def __init__(self, user_id: str, organization_id: str = "default", key_dir: str = "./secure_keys"):
        """
        Initialize the JnxBetaSec encryption system.
        
        Args:
            user_id: Unique identifier for the user
            organization_id: Identifier for the organization (optional)
            key_dir: Directory to store keys
        """
        self.user_id = user_id
        self.organization_id = organization_id
        self.backend = default_backend()
        self.key_dir = Path(key_dir)
        
        self._load_or_generate_keys()
    
    def _load_or_generate_keys(self) -> None:
        """Load existing keys or generate new ones if they don't exist."""
        self.key_dir.mkdir(exist_ok=True, parents=True)
        
        private_key_path = self.key_dir / f"{self.user_id}_private.pem"
        public_key_path = self.key_dir / f"{self.user_id}_public.pem"
        
        if private_key_path.exists() and public_key_path.exists():
            with open(private_key_path, "rb") as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None, 
                    backend=self.backend
                )
            
            with open(public_key_path, "rb") as f:
                self.public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=self.backend
                )
            logger.info(f"Loaded existing keys for user {self.user_id}")
        else:
            logger.info(f"Generating new RSA key pair for user {self.user_id}...")
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=self.backend
            )
            self.public_key = self.private_key.public_key()
            
            with open(private_key_path, "wb") as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            with open(public_key_path, "wb") as f:
                f.write(self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            logger.info(f"Generated and saved new keys for user {self.user_id}")
    
    def export_key(self, key_type: str, output_path: str) -> None:
        """
        Export a key to a file.
        
        Args:
            key_type: Type of key to export ('public' or 'private')
            output_path: Path to save the key
        """
        if key_type.lower() == 'public':
            with open(output_path, "wb") as f:
                f.write(self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
        elif key_type.lower() == 'private':
            with open(output_path, "wb") as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
        else:
            raise ValueError("Key type must be 'public' or 'private'")
    
    def _derive_keys(self, password: str, salt: bytes) -> Tuple[bytes, bytes]:
        """
        Derive encryption keys from password using PBKDF2.
        
        Args:
            password: User's password
            salt: Random salt for key derivation
            
        Returns:
            Tuple of (aes_key, chacha_key)
        """
        password_bytes = password.encode('utf-8')
        
        kdf_aes = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=self.KEY_LENGTH,
            salt=salt,
            iterations=self.ITERATIONS,
            backend=self.backend
        )
        aes_key = kdf_aes.derive(password_bytes)
        
        kdf_chacha = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=self.KEY_LENGTH,
            salt=hashlib.sha256(salt).digest(), 
            iterations=self.ITERATIONS // 2,  
            backend=self.backend
        )
        chacha_key = kdf_chacha.derive(aes_key) 
        
        return aes_key, chacha_key
    
    def _generate_file_metadata(self, file_path: Path, content_type: str) -> Dict[str, Any]:
        """
        Generate metadata for the file being encrypted.
        
        Args:
            file_path: Path to the original file
            content_type: Type of content (image/text)
            
        Returns:
            Dictionary containing file metadata
        """
        file_hash = hashlib.sha512()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                file_hash.update(chunk)
        
        stats = file_path.stat()
        
        metadata = {
            "filename": file_path.name,
            "original_extension": file_path.suffix,
            "content_type": content_type,
            "file_size": stats.st_size,
            "created_date": datetime.datetime.fromtimestamp(stats.st_ctime).isoformat(),
            "modified_date": datetime.datetime.fromtimestamp(stats.st_mtime).isoformat(),
            "encrypted_date": datetime.datetime.now().isoformat(),
            "encryption_version": self.VERSION,
            "sha512_hash": file_hash.hexdigest(),
            "user_id": self.user_id,
            "organization_id": self.organization_id,
        }
        
        if content_type == "image" and PIL_AVAILABLE:
            try:
                with Image.open(file_path) as img:
                    metadata["image_width"] = img.width
                    metadata["image_height"] = img.height
                    metadata["image_format"] = img.format
                    metadata["image_mode"] = img.mode
            except Exception as e:
                logger.warning(f"Could not extract image metadata: {e}")
        
        return metadata
    
    def encrypt_file(self, file_path: str, password: str, content_type: Optional[str] = None) -> str:
        """
        Encrypt a file using the multi-layered JnxBetaSec encryption system.
        
        Args:
            file_path: Path to the file to encrypt
            password: User's password
            content_type: Type of content ("image" or "text"), auto-detected if None
            
        Returns:
            Path to the encrypted .jnx file
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        if content_type is None:
            if file_path.suffix.lower() in ['.jpg', '.jpeg', '.png', '.tif', '.tiff', '.bmp', '.gif']:
                content_type = "image"
            else:
                content_type = "text"
        
        logger.info(f"Encrypting {content_type} file: {file_path}")
        
        salt = os.urandom(32)
        aes_key, chacha_key = self._derive_keys(password, salt)
        
        aes_iv = os.urandom(12)  # 96 bits for AES-GCM
        chacha_nonce = os.urandom(12)  # 96 bits for ChaCha20-Poly1305
        
        output_path = file_path.with_suffix(".jnx")
        
        try:
            with open(file_path, "rb") as f:
                file_content = f.read()
            metadata = self._generate_file_metadata(file_path, content_type)
            metadata_json = json.dumps(metadata).encode('utf-8')
            
            # Layer 1: AES-256-GCM encryption
            aes_cipher = AESGCM(aes_key)
            encrypted_content = aes_cipher.encrypt(aes_iv, file_content, b"JNXL1")
            
            # Layer 2: ChaCha20-Poly1305 encryption
            chacha_cipher = ChaCha20Poly1305(chacha_key)
            doubly_encrypted = chacha_cipher.encrypt(chacha_nonce, encrypted_content, b"JNXL2")
            
            # Encrypt metadata with AES-256-GCM
            encrypted_metadata = aes_cipher.encrypt(
                aes_iv, 
                metadata_json, 
                b"JNXMETA"
            )
            
            # Layer 3: RSA encryption of the symmetric keys
            # Combine keys and IVs for RSA encryption
            keys_bundle = json.dumps({
                "aes_key": base64.b64encode(aes_key).decode('utf-8'),
                "aes_iv": base64.b64encode(aes_iv).decode('utf-8'),
                "chacha_key": base64.b64encode(chacha_key).decode('utf-8'),
                "chacha_nonce": base64.b64encode(chacha_nonce).decode('utf-8'),
                "salt": base64.b64encode(salt).decode('utf-8'),
            }).encode('utf-8')
            
            encrypted_keys = self.public_key.encrypt(
                keys_bundle,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA512()),
                    algorithm=hashes.SHA512(),
                    label=None
                )
            )
            
            signature = self.private_key.sign(
                doubly_encrypted + encrypted_metadata,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA512()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA512()
            )
            
            with open(output_path, "wb") as f:
                f.write(self.FILE_SIGNATURE)
                f.write(self.VERSION.encode('utf-8').ljust(8, b'\0'))
                keys_len = len(encrypted_keys).to_bytes(4, byteorder='big')
                f.write(keys_len)
                f.write(encrypted_keys)
                meta_len = len(encrypted_metadata).to_bytes(4, byteorder='big')
                f.write(meta_len)
                f.write(encrypted_metadata)
                sig_len = len(signature).to_bytes(4, byteorder='big')
                f.write(sig_len)
                f.write(signature)
                content_len = len(doubly_encrypted).to_bytes(8, byteorder='big')
                f.write(content_len)
                f.write(doubly_encrypted)
            logger.info(f"File successfully encrypted: {output_path}")
            return str(output_path)
            
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            if output_path.exists():
                output_path.unlink()
            raise
    
    def decrypt_file(self, file_path: str, password: str, output_path: Optional[str] = None) -> str:
        """
        Decrypt a .jnx file.
        
        Args:
            file_path: Path to the encrypted .jnx file
            password: User's password
            output_path: Path where to save the decrypted file (optional)
            
        Returns:
            Path to the decrypted file
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        if not file_path.suffix.lower() == ".jnx":
            raise ValueError("Not a valid JnxBetaSec file")
        
        logger.info(f"Decrypting file: {file_path}")
        
        try:
            with open(file_path, "rb") as f:
                signature = f.read(len(self.FILE_SIGNATURE))
                if signature != self.FILE_SIGNATURE:
                    raise ValueError("Invalid JnxBetaSec file signature")
                
                version = f.read(8).rstrip(b'\0').decode('utf-8')
                if version != self.VERSION:
                    logger.warning(f"File version mismatch: {version} vs {self.VERSION}")
                
                keys_len = int.from_bytes(f.read(4), byteorder='big')
                encrypted_keys = f.read(keys_len)
                meta_len = int.from_bytes(f.read(4), byteorder='big')
                encrypted_metadata = f.read(meta_len)
                sig_len = int.from_bytes(f.read(4), byteorder='big')
                file_signature = f.read(sig_len)
                content_len = int.from_bytes(f.read(8), byteorder='big')
                encrypted_content = f.read(content_len)
            
            try:
                self.public_key.verify(
                    file_signature,
                    encrypted_content + encrypted_metadata,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA512()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA512()
                )
            except Exception:
                raise ValueError("Invalid file signature - file may be tampered with")
            
            decrypted_keys_bundle = self.private_key.decrypt(
                encrypted_keys,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA512()),
                    algorithm=hashes.SHA512(),
                    label=None
                )
            )
            
            keys_data = json.loads(decrypted_keys_bundle.decode('utf-8'))
            aes_key = base64.b64decode(keys_data['aes_key'])
            aes_iv = base64.b64decode(keys_data['aes_iv'])
            chacha_key = base64.b64decode(keys_data['chacha_key'])
            chacha_nonce = base64.b64decode(keys_data['chacha_nonce'])
            salt = base64.b64decode(keys_data['salt'])
            
            derived_aes_key, derived_chacha_key = self._derive_keys(password, salt)
            if not (secrets.compare_digest(derived_aes_key, aes_key) and 
                    secrets.compare_digest(derived_chacha_key, chacha_key)):
                raise ValueError("Invalid password")
            
            # Layer 2 decryption: ChaCha20-Poly1305
            chacha_cipher = ChaCha20Poly1305(chacha_key)
            aes_encrypted = chacha_cipher.decrypt(chacha_nonce, encrypted_content, b"JNXL2")
            
            # Layer 1 decryption: AES-256-GCM
            aes_cipher = AESGCM(aes_key)
            decrypted_content = aes_cipher.decrypt(aes_iv, aes_encrypted, b"JNXL1")
            
            # Decrypt metadata
            decrypted_metadata_json = aes_cipher.decrypt(aes_iv, encrypted_metadata, b"JNXMETA")
            metadata = json.loads(decrypted_metadata_json.decode('utf-8'))
            
            if output_path is None:
                output_dir = file_path.parent / "decrypted"
                output_dir.mkdir(exist_ok=True)
                output_file = output_dir / metadata['filename']
            else:
                output_file = Path(output_path)
            
            with open(output_file, "wb") as f:
                f.write(decrypted_content)
            
            logger.info(f"File successfully decrypted: {output_file}")
            return str(output_file)
            
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise

