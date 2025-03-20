# JnxBetaSec

A comprehensive security library for encryption, hashing, and secure data handling.

<!-- [![PyPI version](https://img.shields.io/pypi/v/jnxbetasec.svg)](https://pypi.org/project/jnxbetasec/)
[![Python Versions](https://img.shields.io/pypi/pyversions/jnxbetasec.svg)](https://pypi.org/project/jnxbetasec/) -->
[![License](https://img.shields.io/pypi/l/jnxbetasec.svg)](https://github.com/JNX03/jnxbetasec/blob/main/LICENSE)

## Features

- Strong file encryption with multi-layer protection
- Secure password hashing and verification
- File integrity verification
- Command-line interface for easy usage
- Importable Python API for integration into your projects

## Installation

```bash
pip install jnxbetasec

```

### Python API Usage

You can also import and use JnxBetaSec in your Python code:

```python
from jnxbetasec import Encryption, Hashing

# Initialize the encryption system
encryptor = Encryption(user_id="user123")

# Encrypt a file
encrypted_file = encryptor.encrypt_file(
    file_path="document.pdf",
    password="your-secure-password"
)
print(f"File encrypted: {encrypted_file}")

# Decrypt a file
decrypted_file = encryptor.decrypt_file(
    file_path="document.jnx",
    password="your-secure-password"
)
print(f"File decrypted: {decrypted_file}")
```

## Project Structure

```plaintext
jnxbetasec/
├── README.md
├── setup.py
├── jnxbetasec/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── encryption.py
│   │   ├── hashing.py
│   │   └── utils.py
│   └── tests/
│       ├── __init__.py
│       ├── test_encryption.py
│       └── test_hashing.py
```

## How to Use JnxBetaSec

The JnxBetaSec library provides both a command-line interface and a Python API for secure file encryption, decryption, and hashing.

### Installation

Once you've downloaded the code, you can install it using pip:

```shellscript
# Navigate to the directory containing setup.py
cd jnxbetasec

# Install the package
pip install .

# Or install in development mode
pip install -e .
```

### Command-line Usage

After installation, you can use JnxBetaSec directly from the command line:

```shellscript
# Encrypt a file
jnxbetasec --encrypt --file document.pdf --password "your-secure-password"

# Decrypt a file
jnxbetasec --decrypt --file document.jnx --password "your-secure-password"

# Generate a hash for a file
jnxbetasec --hash --file document.pdf --algorithm sha256

# Process multiple files in a directory
jnxbetasec --batch --encrypt --directory ./documents/ --password "your-secure-password" --recursive
```

