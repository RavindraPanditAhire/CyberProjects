# Security Tool Suite

A beginner-friendly security toolkit that demonstrates various cybersecurity concepts and tools. This application provides a graphical interface for several common security operations.

## Features

### 1. Password Tools
- **Password Generator**: Create strong passwords with customizable options
  - Adjustable length
  - Include/exclude uppercase, lowercase, numbers, and special characters
- **Password Strength Checker**: Analyze password strength with detailed feedback
  - Length check
  - Character variety check
  - Strength rating

### 2. Encryption Tools
- **Text Encryption/Decryption**: Secure text using Fernet (symmetric encryption)
  - Encrypt plain text
  - Decrypt encrypted text
  - Automatic key generation

### 3. Network Tools
- **Port Scanner**: Scan for open ports on a specified host
  - Custom port range
  - Multi-threaded scanning
  - Results display

### 4. Hash Generator
- **Multiple Hash Algorithms**: Generate hashes using different algorithms
  - MD5
  - SHA-1
  - SHA-256

## Installation

1. Clone the repository
2. Install required packages:
```bash
pip install -r requirements.txt
```

## Usage

Run the application:
```bash
python main.py
```

## Security Concepts Demonstrated

1. **Cryptography**
   - Symmetric encryption
   - Hashing algorithms
   - Secure password generation

2. **Network Security**
   - Port scanning
   - Network reconnaissance

3. **Password Security**
   - Password complexity requirements
   - Strength assessment
   - Secure generation techniques

## Educational Value

This toolkit helps learn about:
- Basic cryptographic operations
- Network security concepts
- Password security best practices
- Python security libraries
- GUI development with tkinter

## Note

This tool is for educational purposes only. Always obtain proper authorization before scanning networks or systems you don't own.
