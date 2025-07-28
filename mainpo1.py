import base64
import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# Constants for method identifiers
METHOD_AES_GCM = b'\x01'
METHOD_CAESAR = b'\x02'
METHOD_RSA = b'\x03'

# Parameters for key derivation
PBKDF2_ITERATIONS = 100_000
KEY_LENGTH = 32  # AES-256

FIXED_PASSWORD = "MyFixedSecretKey"  # Fixed password (demo only)

# --- HELPERS ---
def derive_key(password, salt):
    # Derive AES key from password and salt using PBKDF2 (SHA256)
    return PBKDF2(password, salt, dkLen=KEY_LENGTH, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256)

# --- AES-GCM ENCRYPTION ---
def aes_gcm_encrypt(plaintext, password):
    salt = get_random_bytes(16)
    key = derive_key(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    # Format: method + salt + nonce + tag + ciphertext
    msg = METHOD_AES_GCM + salt + cipher.nonce + tag + ciphertext
    return base64.b64encode(msg).decode()

def aes_gcm_decrypt(encoded, password):
    data = base64.b64decode(encoded)
    if data[0:1] != METHOD_AES_GCM:
        raise ValueError("Invalid AES-GCM data")
    salt = data[1:17]
    nonce = data[17:33]
    tag = data[33:49]
    ciphertext = data[49:]
    key = derive_key(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()

# --- CAESAR CIPHER ---
def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            start = 65 if char.isupper() else 97
            result += chr((ord(char) - start + shift) % 26 + start)
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

def caesar_encrypt_obfuscated(text, shift):
    # Prefix with method byte and base64 encode
    raw = caesar_encrypt(text, shift).encode()
    return base64.b64encode(METHOD_CAESAR + raw).decode()

def caesar_decrypt_obfuscated(encoded, shift):
    data = base64.b64decode(encoded)
    if data[0:1] != METHOD_CAESAR:
        raise ValueError("Invalid Caesar data")
    raw = data[1:].decode()
    return caesar_decrypt(raw, shift)

# --- RSA ENCRYPTION ---
def generate_rsa_keys():
    key = RSA.generate(2048)
    private = key.export_key()
    public = key.publickey().export_key()
    with open("private.pem", "wb") as f: f.write(private)
    with open("public.pem", "wb") as f: f.write(public)
    print("Keys generated: public.pem, private.pem")

def rsa_encrypt(text, pubkey_file):
    with open(pubkey_file, "rb") as f:
        pubkey = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(pubkey)
    cipher_text = cipher.encrypt(text.encode())
    msg = METHOD_RSA + cipher_text
    return base64.b64encode(msg).decode()

def rsa_decrypt(encoded, privkey_file):
    data = base64.b64decode(encoded)
    if data[0:1] != METHOD_RSA:
        raise ValueError("Invalid RSA data")
    cipher_text = data[1:]
    with open(privkey_file, "rb") as f:
        privkey = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(privkey)
    decrypted = cipher.decrypt(cipher_text)
    return decrypted.decode()

# --- HASHING (SHA-256) ---
def hash_text(text):
    return SHA256.new(text.encode()).hexdigest()

# --- USER INTERFACE ---
def main():
    print("\n--- Secure & Obfuscated Encryption Tool ---")
    while True:
        print("\nChoose an option:")
        print("1) Encrypt")
        print("2) Decrypt")
        print("3) Hash")
        print("4) Generate RSA keypair")
        print("5) Exit")
        choice = input("Enter number: ").strip()
        if choice == '1':
            text = input("Enter text: ")
            print("Choose method: [1] AES-GCM [2] Caesar [3] RSA")
            method = input("Enter number: ").strip()
            if method == '1':
                enc = aes_gcm_encrypt(text, FIXED_PASSWORD)
                print("Encrypted (AES-GCM):", enc)
            elif method == '2':
                shift = int(input("Enter shift number (1-25): "))
                enc = caesar_encrypt_obfuscated(text, shift)
                print("Encrypted (Caesar):", enc)
            elif method == '3':
                keyfile = input("Enter public key file (e.g., public.pem): ").strip()
                enc = rsa_encrypt(text, keyfile)
                print("Encrypted (RSA):", enc)
            else:
                print("Invalid method.")
        elif choice == '2':
            enc_text = input("Enter encrypted text: ")
            # Detect method by the prefix of decoded base64
            try:
                data = base64.b64decode(enc_text)
                method_byte = data[0:1]
            except Exception:
                print("Invalid encoded text!")
                continue

            if method_byte == METHOD_AES_GCM:
                try:
                    dec = aes_gcm_decrypt(enc_text, FIXED_PASSWORD)
                    print("Decrypted (AES-GCM):", dec)
                except Exception as e:
                    print("Decryption failed:", e)
            elif method_byte == METHOD_CAESAR:
                try:
                    shift = int(input("Enter shift number (1-25): "))
                    dec = caesar_decrypt_obfuscated(enc_text, shift)
                    print("Decrypted (Caesar):", dec)
                except Exception as e:
                    print("Decryption failed:", e)
            elif method_byte == METHOD_RSA:
                try:
                    keyfile = input("Enter private key file (e.g., private.pem): ").strip()
                    dec = rsa_decrypt(enc_text, keyfile)
                    print("Decrypted (RSA):", dec)
                except Exception as e:
                    print("Decryption failed:", e)
            else:
                print("Unknown encryption method or corrupted data.")
        elif choice == '3':
            text = input("Enter text to hash: ")
            print("SHA-256 hash:", hash_text(text))
        elif choice == '4':
            generate_rsa_keys()
        elif choice == '5':
            print("Bye!")
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()
