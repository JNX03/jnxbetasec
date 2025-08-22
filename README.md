# SecureKit 🔒

[![PyPI version](https://img.shields.io/pypi/v/securekit.svg)](https://pypi.org/project/securekit)  [![Python Versions](https://img.shields.io/pypi/pyversions/securekit.svg)](https://pypi.org/project/securekit/)  [![npm version](https://img.shields.io/npm/v/securekit.svg)](https://www.npmjs.com/package/securekit)  [![License](https://img.shields.io/pypi/l/securekit.svg)](https://github.com/JNX03/jnxbetasec/blob/main/LICENSE)

**SecureKit** is a comprehensive security toolkit for encryption, hashing, network security, and secure data handling. Available for both Python and Node.js environments with powerful CLI capabilities.

---

## 🚀 Features

### Core Security Features
- **🔐 Advanced Encryption**: Multi-layer file encryption with AES-256
- **🔑 Secure Hashing**: Multiple hash algorithms (SHA-256, SHA-512, MD5, etc.)
- **🔍 File Integrity Checking**: Verify file integrity and detect corruption
- **🗑️ Secure File Deletion**: Military-grade secure file deletion with multiple overwrite passes
- **🔒 Password Generation**: Generate cryptographically secure passwords

### Advanced Security Tools
- **📦 Secure Compression**: Compress and decompress files securely
- **🌐 Network Security Scanning**: Port scanning for security assessment
- **📜 Certificate Validation**: X.509 certificate validation and analysis
- **📊 Log Analysis**: Security log analysis with pattern matching
- **🔍 Batch Processing**: Process multiple files efficiently

### CLI Interface
- **⚡ Modern CLI**: Advanced argument parsing with `--type` parameter
- **🎯 Input Validation**: Built-in sanitization to prevent injection attacks
- **📝 Verbose Logging**: Detailed output with progress indicators
- **🔄 Cross-Platform**: Works on Windows, macOS, and Linux

---

## 📦 Installation

### Python (PyPI)
```bash
pip install securekit
```

### Node.js (npm)
```bash
npm install -g securekit
```

---

## 🛠️ Usage

### Command Line Interface

SecureKit now supports a unified CLI interface with the `--type` parameter for all operations:

#### File Encryption
```bash
securekit --type=encryption --file="document.pdf" --password="your-secure-password"
```

#### File Decryption
```bash
securekit --type=decryption --file="document.pdf.enc" --password="your-secure-password"
```

#### File Hashing
```bash
securekit --type=hash --file="document.pdf" --algorithm=sha256
```

#### Hash Verification
```bash
securekit --type=verify --file="document.pdf" --hash-value="abc123..." --algorithm=sha256
```

#### Password Generation
```bash
securekit --type=password --length=32 --include-symbols
```

#### Secure File Deletion
```bash
securekit --type=secure-delete --file="sensitive-file.txt" --overwrite-passes=7
```

#### File Compression
```bash
securekit --type=compress --file="large-file.txt" --output="compressed.gz"
```

#### File Decompression
```bash
securekit --type=decompress --file="compressed.gz" --output="restored-file.txt"
```

#### Network Port Scanning
```bash
securekit --type=network-scan --host="192.168.1.1" --ports="22,80,443,8080"
```

#### Certificate Validation
```bash
securekit --type=cert-validate --file="certificate.pem" --verbose
```

#### Log Analysis
```bash
securekit --type=log-analysis --file="access.log" --pattern="ERROR|WARN" --verbose
```

#### File Integrity Check
```bash
securekit --type=integrity-check --file="important-file.pdf"
```

### Python API Usage

```python
from securekit import Encryption, Hashing, SecurityUtils

# Encryption
encryptor = Encryption(user_id="user123")
encrypted_file = encryptor.encrypt_file("document.pdf", "password123")

# Hashing
hasher = Hashing()
file_hash = hasher.hash_file("document.pdf", "sha256")

# Security utilities
password = SecurityUtils.generate_password(32, include_symbols=True)
SecurityUtils.secure_delete("sensitive-file.txt")
```

### Node.js API Usage

```javascript
const { Encryption, Hashing, SecurityUtils } = require('securekit');

// Encryption
const encryptor = new Encryption({ userId: 'user123' });
encryptor.encryptFile('document.pdf', 'password123')
  .then(result => console.log(`Encrypted: ${result}`));

// Password generation
const password = SecurityUtils.generatePassword(32, true);
console.log(`Generated password: ${password}`);
```

---

## 🔧 Advanced Features

### 1. **Multi-Pass Secure Deletion**
Securely delete sensitive files with multiple overwrite passes:
```bash
securekit --type=secure-delete --file="secret.txt" --overwrite-passes=10
```

### 2. **Network Security Assessment**
Scan for open ports on target systems:
```bash
securekit --type=network-scan --host="target.example.com" --ports="21,22,23,25,53,80,110,443,993,995"
```

### 3. **Certificate Analysis**
Validate and analyze X.509 certificates:
```bash
securekit --type=cert-validate --file="server.crt" --verbose
```

### 4. **Security Log Analysis**
Search for security patterns in log files:
```bash
securekit --type=log-analysis --file="/var/log/auth.log" --pattern="Failed.*root" --verbose
```

### 5. **Batch Operations**
Process multiple files with batch mode:
```bash
securekit --type=encryption --directory="/sensitive-docs" --password="batch-password" --batch --recursive
```

---

## 🔒 Security Features

- **AES-256 Encryption**: Industry-standard encryption algorithm
- **Secure Random Generation**: Cryptographically secure random number generation
- **Input Sanitization**: Prevents path traversal and injection attacks
- **Memory-Safe Operations**: Secure handling of sensitive data in memory
- **Multi-Platform Security**: Consistent security across different operating systems

---

## 📁 Project Structure

```plaintext
securekit/
├── README.md
├── package.json                # Node.js package configuration
├── setup.py                   # Python package configuration
├── src/                       # TypeScript source code
│   ├── cli.ts                # CLI interface
│   ├── core/
│   │   ├── encryption.ts     # Encryption utilities
│   │   ├── hashing.ts        # Hashing utilities
│   │   └── utils.ts          # Additional utilities
│   └── types.ts              # Type definitions
├── securekit/                # Python package
│   ├── __init__.py
│   ├── cli.py               # Python CLI interface
│   ├── core/
│   │   ├── encryption.py    # Encryption utilities
│   │   ├── hashing.py       # Hashing utilities
│   │   └── utils.py         # Additional utilities
│   └── tests/
└── test/                    # Test suites
```

---

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes with proper testing
4. Commit your changes: `git commit -m 'Add amazing feature'`
5. Push to the branch: `git push origin feature/amazing-feature`
6. Open a Pull Request

---

## 📋 Requirements

### Python
- Python 3.8 or higher
- cryptography>=39.0.0
- click>=8.0.0
- Additional dependencies in `setup.py`

### Node.js
- Node.js 16.0.0 or higher
- TypeScript support
- Additional dependencies in `package.json`

---

## 📄 License

SecureKit is licensed under the [MIT License](LICENSE).

---

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/JNX03/jnxbetasec/issues)
- **Discussions**: [GitHub Discussions](https://github.com/JNX03/jnxbetasec/discussions)
- **Email**: Jn03official@gmail.com

---

## 🔄 Changelog

### Version 2.0.0
- **🎉 Renamed to SecureKit** for better branding
- **⚡ Enhanced CLI** with `--type` parameter system
- **🔒 Added 12+ new security features**:
  - Secure file deletion
  - Password generation
  - File compression/decompression
  - Network port scanning
  - Certificate validation
  - Log analysis
  - File integrity checking
- **🛡️ Improved security** with input validation and sanitization
- **📦 Better package management** for both npm and PyPI
- **🔧 Enhanced error handling** and user experience

---

**Made with ❤️ by [Jnx03](https://github.com/JNX03)**