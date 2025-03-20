Below is an enhanced version of the README.md that highlights both the Python and NPM usage:

---

# JnxBetaSec

[![PyPI version](https://img.shields.io/pypi/v/jnxbetasec.svg)](https://test.pypi.org/project/jnxbetasec)  [![Python Versions](https://img.shields.io/pypi/pyversions/jnxbetasec.svg)](https://test.pypi.org/project/jnxbetasec/)  [![npm version](https://img.shields.io/npm/v/jnxbetasec.svg)](https://www.npmjs.com/package/jnxbetasec)  [![License](https://img.shields.io/pypi/l/jnxbetasec.svg)](https://github.com/JNX03/jnxbetasec/blob/main/LICENSE)

A comprehensive security library for encryption, hashing, and secure data handling, available for both Python and Node.js environments.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
  - [Python](#python)
  - [Node.js (NPM)](#nodejs-npm)
- [Usage](#usage)
  - [Python API](#python-api-usage)
  - [Command-line Interface](#command-line-interface)
  - [Node.js Usage](#nodejs-usage)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **Robust Encryption:** Multi-layer protection for file encryption.
- **Secure Hashing:** Reliable password hashing and verification.
- **Integrity Verification:** Validate file integrity with secure hashing.
- **Command-line Interface:** Easily encrypt, decrypt, and hash files via CLI.
- **API Integration:** Importable modules for seamless integration in your Python projects.
- **Dual Platform Support:** Use in Python projects or integrate in Node.js applications.

---

## Installation

### Python

Install JnxBetaSec via pip:

```bash
pip install jnxbetasec
```

For development, install in editable mode:

```bash
pip install -e .
```

### Node.js (NPM)

Install the Node.js version via npm:

```bash
npm i jnxbetasec
```

For more details, refer to the [NPM package page](https://www.npmjs.com/package/jnxbetasec).

---

## Usage

### Python API Usage

Integrate the library in your Python project by importing the relevant modules:

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

### Command-line Interface

After installation, you can quickly perform security operations via the CLI:

- **Encrypt a file:**

  ```bash
  jnxbetasec --encrypt --file document.pdf --password "your-secure-password"
  ```

- **Decrypt a file:**

  ```bash
  jnxbetasec --decrypt --file document.jnx --password "your-secure-password"
  ```

- **Generate a file hash (e.g., SHA-256):**

  ```bash
  jnxbetasec --hash --file document.pdf --algorithm sha256
  ```

- **Batch process files in a directory (recursive):**

  ```bash
  jnxbetasec --batch --encrypt --directory ./documents/ --password "your-secure-password" --recursive
  ```

### Node.js Usage

For Node.js projects, after installation, you can require the package and utilize its functionalities. (Refer to the [NPM documentation](https://www.npmjs.com/package/jnxbetasec) for complete API details.)

```javascript
const jnxbetasec = require('jnxbetasec');

// Example: Encrypt a file (usage might vary based on your implementation)
jnxbetasec.encryptFile({
  filePath: 'document.pdf',
  password: 'your-secure-password',
  userId: 'user123'
})
.then(encryptedFile => {
  console.log(`File encrypted: ${encryptedFile}`);
})
.catch(err => {
  console.error('Encryption failed:', err);
});
```

---

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

---

## Contributing

Contributions are welcome! If you wish to improve JnxBetaSec:

1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Ensure that all tests pass.
4. Submit a pull request outlining your changes.

---

## License

JnxBetaSec is licensed under the terms of the [MIT License](https://github.com/JNX03/jnxbetasec/blob/main/LICENSE).

---

