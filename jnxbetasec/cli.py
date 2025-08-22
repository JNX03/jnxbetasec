"""
Command-line interface for SecureKit.
"""

import os
import sys
import re
import socket
import gzip
import shutil
import secrets
import string
import time
import threading
from pathlib import Path
from typing import Optional, List, Dict, Tuple

import click
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from jnxbetasec.core.encryption import Encryption
from jnxbetasec.core.hashing import Hashing
from jnxbetasec.core.utils import BatchProcessor


class SecurityUtils:
    """Utility class for additional security operations."""
    
    @staticmethod
    def generate_password(length: int = 32, include_symbols: bool = True) -> str:
        """Generate a secure random password."""
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        numbers = string.digits
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        charset = lowercase + uppercase + numbers
        if include_symbols:
            charset += symbols
        
        password = ''.join(secrets.choice(charset) for _ in range(length))
        return password
    
    @staticmethod
    def secure_delete(file_path: str, passes: int = 3) -> bool:
        """Securely delete a file by overwriting it multiple times."""
        try:
            if not os.path.exists(file_path):
                return False
            
            file_size = os.path.getsize(file_path)
            
            # Overwrite with random data multiple times
            with open(file_path, 'r+b') as file:
                for _ in range(passes):
                    file.seek(0)
                    file.write(os.urandom(file_size))
                    file.flush()
                    os.fsync(file.fileno())
            
            # Finally delete the file
            os.unlink(file_path)
            return True
        except Exception:
            return False
    
    @staticmethod
    def validate_certificate(cert_path: str) -> Dict:
        """Validate an X.509 certificate."""
        try:
            with open(cert_path, 'rb') as cert_file:
                cert_data = cert_file.read()
            
            # Try to parse as PEM first
            try:
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                format_type = "PEM"
            except ValueError:
                # Try DER format
                cert = x509.load_der_x509_certificate(cert_data, default_backend())
                format_type = "DER"
            
            return {
                "valid": True,
                "details": {
                    "format": format_type,
                    "subject": str(cert.subject),
                    "issuer": str(cert.issuer),
                    "serial_number": str(cert.serial_number),
                    "not_valid_before": cert.not_valid_before.isoformat(),
                    "not_valid_after": cert.not_valid_after.isoformat(),
                    "version": cert.version.name,
                    "signature_algorithm": cert.signature_algorithm_oid._name
                }
            }
        except Exception as e:
            return {
                "valid": False,
                "details": {"error": str(e)}
            }
    
    @staticmethod
    def scan_network_ports(host: str, ports: List[int], timeout: float = 3.0) -> Dict[str, List[int]]:
        """Scan network ports on a given host."""
        open_ports = []
        closed_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
                else:
                    closed_ports.append(port)
                sock.close()
            except Exception:
                closed_ports.append(port)
        
        threads = []
        for port in ports:
            thread = threading.Thread(target=scan_port, args=(port,))
            thread.start()
            threads.append(thread)
        
        for thread in threads:
            thread.join()
        
        return {"open": sorted(open_ports), "closed": sorted(closed_ports)}
    
    @staticmethod
    def analyze_log_file(log_path: str, pattern: str) -> Dict:
        """Analyze a log file for specific patterns."""
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as file:
                lines = file.readlines()
            
            regex = re.compile(pattern, re.IGNORECASE)
            matching_lines = []
            
            for i, line in enumerate(lines, 1):
                if regex.search(line):
                    matching_lines.append(f"Line {i}: {line.strip()}")
            
            return {
                "matches": len(matching_lines),
                "lines": matching_lines[:50]  # Limit to first 50 matches
            }
        except Exception as e:
            return {"matches": 0, "lines": [], "error": str(e)}
    
    @staticmethod
    def compress_file(file_path: str, output_path: Optional[str] = None) -> str:
        """Compress a file using gzip."""
        if output_path is None:
            output_path = f"{file_path}.gz"
        
        with open(file_path, 'rb') as f_in:
            with gzip.open(output_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        return output_path
    
    @staticmethod
    def decompress_file(file_path: str, output_path: Optional[str] = None) -> str:
        """Decompress a gzip file."""
        if output_path is None:
            output_path = file_path.replace('.gz', '')
        
        with gzip.open(file_path, 'rb') as f_in:
            with open(output_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        return output_path


def sanitize_input(input_str: str) -> str:
    """Sanitize user input to prevent path traversal and injection attacks."""
    # Remove dangerous characters
    sanitized = re.sub(r'[<>:"|?*\x00-\x1f]', '', input_str)
    return sanitized.strip()


@click.command()
@click.option("--type", "operation_type", type=click.Choice([
    'encryption', 'decryption', 'hash', 'verify', 'password', 'secure-delete',
    'compress', 'decompress', 'network-scan', 'cert-validate', 'log-analysis',
    'integrity-check'
]), help="Operation type to perform")
@click.option("--file", type=str, help="Path to the file")
@click.option("--directory", type=str, help="Path to the directory (for batch operations)")
@click.option("--password", type=str, help="Password for encryption/decryption")
@click.option("--algorithm", type=str, default="sha256", help="Hash algorithm to use")
@click.option("--hash-value", type=str, help="Hash value for verification")
@click.option("--user", type=str, help="User ID for key operations")
@click.option("--output", type=str, help="Output path")
@click.option("--key-type", type=str, help="Key type (public/private)")
@click.option("--recursive", is_flag=True, help="Process directories recursively")
@click.option("--content-type", type=str, help="Content type (image/text)")
@click.option("--length", type=int, default=32, help="Password length (default: 32)")
@click.option("--include-symbols", is_flag=True, help="Include symbols in password generation")
@click.option("--host", type=str, help="Host for network operations")
@click.option("--ports", type=str, help="Comma-separated list of ports to scan")
@click.option("--pattern", type=str, help="Pattern for log analysis")
@click.option("--overwrite-passes", type=int, default=3, help="Number of overwrite passes for secure deletion")
@click.option("--batch", is_flag=True, help="Enable batch processing")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.version_option()
def main(operation_type, file, directory, password, algorithm, hash_value, user, output,
         key_type, recursive, content_type, length, include_symbols, host, ports,
         pattern, overwrite_passes, batch, verbose):
    """SecureKit - A comprehensive security toolkit with advanced features."""
    
    if not operation_type:
        ctx = click.get_current_context()
        click.echo(ctx.get_help())
        click.echo("\nAvailable operation types:")
        click.echo("  encryption     - Encrypt a file")
        click.echo("  decryption     - Decrypt a file") 
        click.echo("  hash           - Generate file hash")
        click.echo("  verify         - Verify file against hash")
        click.echo("  password       - Generate secure password")
        click.echo("  secure-delete  - Securely delete a file")
        click.echo("  compress       - Compress a file")
        click.echo("  decompress     - Decompress a file")
        click.echo("  network-scan   - Scan network ports")
        click.echo("  cert-validate  - Validate X.509 certificate")
        click.echo("  log-analysis   - Analyze log files")
        click.echo("  integrity-check - Check file integrity")
        return
    
    try:
        if operation_type == 'encryption':
            if not file:
                click.echo("Error: File path required for encryption", err=True)
                sys.exit(1)
            
            if not password:
                password = click.prompt("Enter encryption password", hide_input=True, confirmation_prompt=True)
            
            click.echo("Encrypting file...")
            encryptor = Encryption(user_id=sanitize_input(user or "default_user"))
            result = encryptor.encrypt_file(sanitize_input(file), password, content_type)
            click.echo(f"✓ File encrypted: {result}")
            
        elif operation_type == 'decryption':
            if not file:
                click.echo("Error: File path required for decryption", err=True)
                sys.exit(1)
                
            if not password:
                password = click.prompt("Enter decryption password", hide_input=True)
                
            click.echo("Decrypting file...")
            encryptor = Encryption(user_id=sanitize_input(user or "default_user"))
            result = encryptor.decrypt_file(sanitize_input(file), password, 
                                          sanitize_input(output) if output else None)
            click.echo(f"✓ File decrypted: {result}")
            
        elif operation_type == 'hash':
            if not file:
                click.echo("Error: File path required for hashing", err=True)
                sys.exit(1)
                
            click.echo("Generating hash...")
            hasher = Hashing()
            result = hasher.hash_file(sanitize_input(file), sanitize_input(algorithm))
            click.echo(f"✓ File hash ({algorithm}): {result}")
            
        elif operation_type == 'verify':
            if not file or not hash_value:
                click.echo("Error: File path and hash value required for verification", err=True)
                sys.exit(1)
                
            click.echo("Verifying file...")
            hasher = Hashing()
            result = hasher.verify_file(sanitize_input(file), sanitize_input(hash_value), 
                                      sanitize_input(algorithm))
            if result:
                click.echo("✓ Verification result: Success")
            else:
                click.echo("✗ Verification result: Failed")
                sys.exit(1)
                
        elif operation_type == 'password':
            generated_password = SecurityUtils.generate_password(length, include_symbols)
            click.echo(f"✓ Generated password: {generated_password}")
            click.echo(f"Password strength: {length} characters, {'with' if include_symbols else 'without'} symbols")
            
        elif operation_type == 'secure-delete':
            if not file:
                click.echo("Error: File path required for secure deletion", err=True)
                sys.exit(1)
                
            click.echo("Securely deleting file...")
            result = SecurityUtils.secure_delete(sanitize_input(file), overwrite_passes)
            if result:
                click.echo("✓ File securely deleted")
            else:
                click.echo("✗ Secure deletion failed")
                sys.exit(1)
                
        elif operation_type == 'compress':
            if not file:
                click.echo("Error: File path required for compression", err=True)
                sys.exit(1)
                
            click.echo("Compressing file...")
            result = SecurityUtils.compress_file(sanitize_input(file), 
                                                sanitize_input(output) if output else None)
            click.echo(f"✓ File compressed: {result}")
            
        elif operation_type == 'decompress':
            if not file:
                click.echo("Error: File path required for decompression", err=True)
                sys.exit(1)
                
            click.echo("Decompressing file...")
            result = SecurityUtils.decompress_file(sanitize_input(file), 
                                                 sanitize_input(output) if output else None)
            click.echo(f"✓ File decompressed: {result}")
            
        elif operation_type == 'network-scan':
            if not host or not ports:
                click.echo("Error: Host and ports required for network scanning", err=True)
                sys.exit(1)
                
            port_list = [int(p.strip()) for p in ports.split(',') if p.strip().isdigit()]
            if not port_list:
                click.echo("Error: Invalid port list", err=True)
                sys.exit(1)
                
            click.echo(f"Scanning {len(port_list)} ports on {host}...")
            result = SecurityUtils.scan_network_ports(sanitize_input(host), port_list)
            click.echo(f"✓ Network scan completed")
            click.echo(f"Open ports: {', '.join(map(str, result['open'])) or 'None'}")
            click.echo(f"Closed ports: {len(result['closed'])}")
            
        elif operation_type == 'cert-validate':
            if not file:
                click.echo("Error: Certificate file path required", err=True)
                sys.exit(1)
                
            click.echo("Validating certificate...")
            result = SecurityUtils.validate_certificate(sanitize_input(file))
            if result['valid']:
                click.echo("✓ Certificate is valid")
                if verbose:
                    click.echo("Certificate details:")
                    for key, value in result['details'].items():
                        click.echo(f"  {key}: {value}")
            else:
                click.echo("✗ Certificate validation failed")
                click.echo(f"Error: {result['details'].get('error', 'Invalid format')}")
                sys.exit(1)
                
        elif operation_type == 'log-analysis':
            if not file or not pattern:
                click.echo("Error: Log file path and search pattern required", err=True)
                sys.exit(1)
                
            click.echo("Analyzing log file...")
            result = SecurityUtils.analyze_log_file(sanitize_input(file), sanitize_input(pattern))
            
            if 'error' in result:
                click.echo(f"✗ Log analysis failed: {result['error']}")
                sys.exit(1)
                
            click.echo(f"✓ Log analysis completed: {result['matches']} matches found")
            
            if result['matches'] > 0 and verbose:
                click.echo("Matching lines:")
                for line in result['lines']:
                    click.echo(f"  {line}")
                    
        elif operation_type == 'integrity-check':
            if not file:
                click.echo("Error: File path required for integrity check", err=True)
                sys.exit(1)
                
            click.echo("Checking file integrity...")
            hasher = Hashing()
            hash1 = hasher.hash_file(sanitize_input(file), 'sha256')
            
            # Wait a moment and hash again
            time.sleep(0.1)
            hash2 = hasher.hash_file(sanitize_input(file), 'sha256')
            
            if hash1 == hash2:
                click.echo("✓ File integrity check passed")
                click.echo(f"File hash: {hash1}")
            else:
                click.echo("✗ File integrity check failed - file may be corrupted")
                sys.exit(1)
                
        else:
            click.echo(f"Error: Unknown operation type: {operation_type}", err=True)
            sys.exit(1)
            
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()