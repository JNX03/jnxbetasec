"""
Command-line interface for JnxBetaSec.
"""

import os
import sys
import click
from pathlib import Path
from typing import Optional

from jnxbetasec.core.encryption import Encryption
from jnxbetasec.core.hashing import Hashing
from jnxbetasec.core.utils import BatchProcessor


@click.group(invoke_without_command=True)
@click.option("--encrypt", is_flag=True, help="Encrypt a file")
@click.option("--decrypt", is_flag=True, help="Decrypt a file")
@click.option("--hash", is_flag=True, help="Generate a hash for a file")
@click.option("--verify", is_flag=True, help="Verify a file against a hash")
@click.option("--generate-keys", is_flag=True, help="Generate a new key pair")
@click.option("--export-key", is_flag=True, help="Export a key")
@click.option("--batch", is_flag=True, help="Process multiple files")
@click.option("--file", type=str, help="Path to the file")
@click.option("--directory", type=str, help="Path to the directory (for batch operations)")
@click.option("--password", type=str, help="Password for encryption/decryption")
@click.option("--algorithm", type=str, default="sha256", help="Hash algorithm to use")
@click.option("--hash-value", type=str, help="Hash value for verification")
@click.option("--user", type=str, help="User ID for key operations")
@click.option("--output", type=str, help="Output path")
@click.option("--type", type=str, help="Key type (public/private)")
@click.option("--recursive", is_flag=True, help="Process directories recursively")
@click.option("--content-type", type=str, help="Content type (image/text)")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.version_option()
def main(encrypt, decrypt, hash, verify, generate_keys, export_key, batch,
         file, directory, password, algorithm, hash_value, user, output, 
         type, recursive, content_type, verbose):
    """JnxBetaSec - A comprehensive security library."""
    
    # Configure verbosity
    import logging
    log_level = logging.INFO if verbose else logging.WARNING
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # No command specified, show help
    if not any([encrypt, decrypt, hash, verify, generate_keys, export_key, batch]):
        click.echo(main.get_help(click.Context(main)))
        return
    
    try:
        # Single file operations
        if encrypt and file:
            if not password:
                password = click.prompt("Enter encryption password", hide_input=True, confirmation_prompt=True)
            
            encryptor = Encryption(user_id=user or "default_user")
            result = encryptor.encrypt_file(file, password, content_type)
            click.echo(f"File encrypted: {result}")
            
        elif decrypt and file:
            if not password:
                password = click.prompt("Enter decryption password", hide_input=True)
                
            encryptor = Encryption(user_id=user or "default_user")
            result = encryptor.decrypt_file(file, password, output)
            click.echo(f"File decrypted: {result}")
            
        elif hash and file:
            hasher = Hashing()
            result = hasher.hash_file(file, algorithm)
            click.echo(f"File hash ({algorithm}): {result}")
            
        elif verify and file and hash_value:
            hasher = Hashing()
            result = hasher.verify_file(file, hash_value, algorithm)
            click.echo(f"Verification result: {'Success' if result else 'Failed'}")
            
        elif generate_keys:
            user_id = user or click.prompt("Enter user ID")
            output_dir = output or "./keys"
            encryptor = Encryption(user_id=user_id, key_dir=output_dir)
            click.echo(f"Keys generated for user {user_id} in {output_dir}")
            
        elif export_key and user and type:
            output_path = output or f"./{user}_{type}.pem"
            encryptor = Encryption(user_id=user)
            encryptor.export_key(type, output_path)
            click.echo(f"{type.capitalize()} key exported to {output_path}")
            
        # Batch operations
        elif batch and directory:
            if not password and (encrypt or decrypt):
                password = click.prompt("Enter password", hide_input=True, confirmation_prompt=True)
                
            processor = BatchProcessor()
            
            if encrypt:
                results = processor.encrypt_directory(directory, password, recursive, content_type)
                click.echo(f"Batch encryption completed: {len(results)} files processed")
                
            elif decrypt:
                results = processor.decrypt_directory(directory, password, recursive, output)
                click.echo(f"Batch decryption completed: {len(results)} files processed")
                
            elif hash:
                results = processor.hash_directory(directory, algorithm, recursive)
                for file_path, file_hash in results.items():
                    click.echo(f"{file_path}: {file_hash}")
                    
        else:
            click.echo("Invalid command combination. See --help for usage information.")
            
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()

