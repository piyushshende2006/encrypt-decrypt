# encrypt-decrypt
Python tool for encryption and decryption

Secure & Obfuscated Encryption Tool
===================================

A simple Python-based command-line tool that supports secure encryption, decryption, hashing, and RSA key generation.

------------------------------------------------------------
Features:
------------------------------------------------------------
1. AES-GCM encryption/decryption with key derivation (PBKDF2 + SHA-256)
2. Caesar Cipher encryption (with Base64 obfuscation)
3. RSA encryption/decryption using 2048-bit keys
4. SHA-256 hashing of any text
5. RSA key pair generation (public.pem / private.pem)
6. Auto-detection of encryption method during decryption

------------------------------------------------------------
Dependencies:
------------------------------------------------------------
- Python 3.6 or higher
- pycryptodome library

Install using:
> pip install pycryptodome

------------------------------------------------------------
How to Use:
------------------------------------------------------------
Run the script:
> python your_script_name.py

Choose options from the menu:
1) Encrypt
2) Decrypt
3) Hash
4) Generate RSA keypair
5) Exit

------------------------------------------------------------
Encryption Methods:
------------------------------------------------------------

[AES-GCM]
- Secure encryption using a fixed password (demo purpose)
- Combines salt, nonce, tag and ciphertext in output
- Encoded in Base64

[Caesar Cipher]
- Letter-shift cipher with Base64 encoded output
- Prefixed with a method identifier

[RSA]
- Asymmetric encryption using OAEP padding
- Public and Private keys stored in PEM files

[Hashing]
- SHA-256 hash output for given text

------------------------------------------------------------
Example:
------------------------------------------------------------
> Enter text: Hello World
> Choose method: [1] AES-GCM [2] Caesar [3] RSA
> 1
> Encrypted (AES-GCM): <base64-encoded>

> Decrypted (AES-GCM): Hello World

------------------------------------------------------------
Notes:
------------------------------------------------------------
- AES uses a fixed password ("MyFixedSecretKey") for demonstration.
  You should replace it with a secure method for production.
- Caesar cipher is not cryptographically secure. It’s for basic obfuscation or learning only.

------------------------------------------------------------
License:
------------------------------------------------------------
This project is released under the MIT License.
