# ══════════════════════════════════════════════════════════════════════════════
#  FILE ENCRYPTOR & DECRYPTOR
#  Uses AES-256 encryption — the same standard used by banks and governments
#  Author: Fatima Koumayha

# ══════════════════════════════════════════════════════════════════════════════

# ── What is AES-256? ──────────────────────────────────────────────────────────
# AES = Advanced Encryption Standard
# 256 = the key is 256 bits long (extremely hard to crack)
# It works by scrambling your file's data using a secret key (your password)
# Without the correct password, the file looks like random noise

import os           # to work with files and folders on your computer
import sys          # to exit the program if something goes wrong
import hashlib      # to convert your password into a proper 256-bit key
import secrets      # to generate truly random numbers (safer than random)
import struct       # to pack/unpack numbers into bytes (for file size)
import getpass      # to hide password input (shows * instead of letters)
from pathlib import Path  # makes working with file paths easier

# ── Try to import the encryption library ──────────────────────────────────────
# Cryptography is NOT built into Python — we need to install it
# Run: pip install cryptography
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("❌ Missing library! Run: pip install cryptography")
    sys.exit(1)

# ══════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

# How many bytes the "salt" will be
# Salt = random data added to your password before hashing
# Why? So two people with the same password get DIFFERENT encryption keys
# This prevents "rainbow table" attacks (pre-computed password databases)
SALT_SIZE = 32          # 32 bytes = 256 bits

# IV = Initialization Vector — random data that makes each encryption unique
# Even if you encrypt the same file twice with the same password,
# the result will be different each time because the IV is random
IV_SIZE = 16            # 16 bytes = 128 bits (required by AES)

# How many times we hash the password to make it harder to brute-force
# 100,000 iterations means an attacker has to do 100,000x more work
ITERATIONS = 100_000

# The file extension we add to encrypted files
ENCRYPTED_EXTENSION = ".encrypted"

# ══════════════════════════════════════════════════════════════════════════════
#  CORE FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Convert a human password into a proper 256-bit AES encryption key.

    WHY? AES needs exactly 32 bytes (256 bits) as a key.
    A password like "hello123" is only 8 bytes — not enough.
    We use PBKDF2 (Password-Based Key Derivation Function 2) to stretch it.

    PBKDF2 works like this:
    1. Takes your password + salt
    2. Hashes them together 100,000 times using SHA-256
    3. Returns a perfect 32-byte key

    This makes brute-force attacks 100,000x harder.
    """
    key = hashlib.pbkdf2_hmac(
        "sha256",        # the hashing algorithm to use
        password.encode("utf-8"),  # convert password string to bytes
        salt,            # the random salt
        ITERATIONS,      # how many times to hash (makes brute-force harder)
        dklen=32         # output exactly 32 bytes (256 bits) for AES-256
    )
    return key


def encrypt_file(input_path: str, password: str) -> str:
    """
    Encrypt a file using AES-256-CBC encryption.

    HOW IT WORKS:
    1. Generate random salt and IV
    2. Derive a 256-bit key from password + salt
    3. Read the original file
    4. Encrypt the data using AES-256
    5. Save: [salt][iv][original_size][encrypted_data] → .encrypted file

    WHY save original_size?
    AES works in 16-byte blocks. If the file isn't a multiple of 16 bytes,
    we add padding. We save the original size so we can remove padding on decrypt.
    """

    input_path = Path(input_path)

    # Check the file exists
    if not input_path.exists():
        raise FileNotFoundError(f"File not found: {input_path}")

    # Don't encrypt an already encrypted file
    if input_path.suffix == ENCRYPTED_EXTENSION:
        raise ValueError("This file is already encrypted!")

    # ── Step 1: Generate random salt and IV ───────────────────────────────
    # secrets.token_bytes() generates cryptographically secure random bytes
    # This is MUCH safer than random.random() which is predictable
    salt = secrets.token_bytes(SALT_SIZE)   # random salt (32 bytes)
    iv   = secrets.token_bytes(IV_SIZE)     # random IV (16 bytes)

    # ── Step 2: Derive the encryption key from password + salt ────────────
    key = derive_key(password, salt)

    # ── Step 3: Read the original file ────────────────────────────────────
    # "rb" = read binary — reads raw bytes, works for ANY file type
    # (photos, PDFs, videos, Word docs, etc.)
    with open(input_path, "rb") as f:
        original_data = f.read()

    original_size = len(original_data)  # remember the exact original size

    # ── Step 4: Pad the data to a multiple of 16 bytes ────────────────────
    # AES-CBC works in 16-byte blocks. If data isn't a multiple of 16,
    # we add extra bytes (padding) to make it fit.
    pad_length = 16 - (len(original_data) % 16)
    padded_data = original_data + bytes([pad_length] * pad_length)

    # ── Step 5: Create AES-256-CBC cipher and encrypt ─────────────────────
    # CBC = Cipher Block Chaining
    # Each block of encrypted data depends on the previous block
    # This means identical data blocks produce DIFFERENT encrypted blocks
    cipher = Cipher(
        algorithms.AES(key),     # use AES with our 256-bit key
        modes.CBC(iv),           # use CBC mode with our random IV
        backend=default_backend()
    )
    encryptor = cipher.encryptor()

    # Encrypt the padded data
    # update() encrypts the data, finalize() finishes the process
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # ── Step 6: Save the encrypted file ───────────────────────────────────
    # We save everything needed to decrypt later:
    # [salt (32 bytes)] [iv (16 bytes)] [original_size (8 bytes)] [encrypted data]
    output_path = Path(str(input_path) + ENCRYPTED_EXTENSION)

    with open(output_path, "wb") as f:  # "wb" = write binary
        f.write(salt)                          # 32 bytes: salt
        f.write(iv)                            # 16 bytes: IV
        f.write(struct.pack("<Q", original_size))  # 8 bytes: original file size
        f.write(encrypted_data)                # rest: the encrypted data

    return str(output_path)


def decrypt_file(input_path: str, password: str) -> str:
    """
    Decrypt a file that was encrypted by this tool.

    HOW IT WORKS (reverse of encrypt):
    1. Read [salt][iv][original_size][encrypted_data] from the file
    2. Derive the key from password + salt
    3. Decrypt the data using AES-256
    4. Remove padding using original_size
    5. Save the original file
    """

    input_path = Path(input_path)

    # Check the file exists and is an encrypted file
    if not input_path.exists():
        raise FileNotFoundError(f"File not found: {input_path}")

    if input_path.suffix != ENCRYPTED_EXTENSION:
        raise ValueError("This file doesn't appear to be encrypted by this tool.")

    # ── Step 1: Read the encrypted file ───────────────────────────────────
    with open(input_path, "rb") as f:
        salt          = f.read(SALT_SIZE)       # first 32 bytes = salt
        iv            = f.read(IV_SIZE)         # next 16 bytes = IV
        size_data     = f.read(8)               # next 8 bytes = original size
        encrypted_data = f.read()              # rest = encrypted data

    # Unpack the original file size from bytes back to an integer
    original_size = struct.unpack("<Q", size_data)[0]

    # ── Step 2: Derive the same key using same password + salt ────────────
    # If the password is WRONG, derive_key still runs but produces a WRONG key
    # The decryption will either fail or produce garbage data
    key = derive_key(password, salt)

    # ── Step 3: Decrypt the data ───────────────────────────────────────────
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()

    try:
        decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
    except Exception:
        raise ValueError("❌ Wrong password or corrupted file!")

    # ── Step 4: Remove padding ────────────────────────────────────────────
    # Cut the data to the original size (removes any padding bytes)
    decrypted_data = decrypted_padded[:original_size]

    # Basic check: if decrypted data is empty, password was probably wrong
    if len(decrypted_data) == 0:
        raise ValueError("❌ Wrong password or corrupted file!")

    # ── Step 5: Save the decrypted file ───────────────────────────────────
    # Remove the .encrypted extension to get the original filename
    output_path = Path(str(input_path).replace(ENCRYPTED_EXTENSION, ""))

    # If the original file still exists, add "_decrypted" to avoid overwriting
    if output_path.exists():
        stem   = output_path.stem
        suffix = output_path.suffix
        output_path = output_path.parent / f"{stem}_decrypted{suffix}"

    with open(output_path, "wb") as f:
        f.write(decrypted_data)

    return str(output_path)


def get_file_info(file_path: str) -> dict:
    """Get basic info about a file (size, type, encrypted or not)."""
    path = Path(file_path)
    size = path.stat().st_size

    # Convert bytes to human-readable format
    if size < 1024:
        size_str = f"{size} bytes"
    elif size < 1024 ** 2:
        size_str = f"{size/1024:.1f} KB"
    elif size < 1024 ** 3:
        size_str = f"{size/1024**2:.1f} MB"
    else:
        size_str = f"{size/1024**3:.1f} GB"

    return {
        "name":      path.name,
        "size":      size_str,
        "type":      path.suffix or "no extension",
        "encrypted": path.suffix == ENCRYPTED_EXTENSION
    }


# ══════════════════════════════════════════════════════════════════════════════
#  DISPLAY HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def print_banner():
    print("\n" + "═" * 55)
    print("  🔒  FILE ENCRYPTOR & DECRYPTOR")
    print("  AES-256 Military-Grade Encryption")
    print("═" * 55)

def print_menu():
    print("\n  What do you want to do?")
    print("  [1] 🔒 Encrypt a file")
    print("  [2] 🔓 Decrypt a file")
    print("  [3] ℹ️  File info")
    print("  [4] ❌ Exit")
    print()


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN PROGRAM
# ══════════════════════════════════════════════════════════════════════════════

def main():
    print_banner()

    while True:
        print_menu()
        choice = input("  Enter choice (1-4): ").strip()

        # ── Encrypt ───────────────────────────────────────────────────────
        if choice == "1":
            print("\n  🔒 ENCRYPT FILE")
            print("  ─────────────────────────────────────────")
            file_path = input("  File path to encrypt: ").strip().strip('"')

            if not os.path.exists(file_path):
                print(f"  ❌ File not found: {file_path}")
                continue

            # getpass hides the password as you type (shows nothing)
            password = getpass.getpass("  Enter encryption password: ")
            if not password:
                print("  ❌ Password cannot be empty.")
                continue

            # Ask to confirm password (avoid typos)
            confirm = getpass.getpass("  Confirm password: ")
            if password != confirm:
                print("  ❌ Passwords do not match!")
                continue

            print("\n  ⏳ Encrypting... (this may take a moment for large files)")

            try:
                output = encrypt_file(file_path, password)
                info   = get_file_info(output)
                print(f"\n  ✅ File encrypted successfully!")
                print(f"  📁 Output file : {output}")
                print(f"  📦 File size   : {info['size']}")
                print(f"\n  ⚠️  Keep your password safe — without it, the file CANNOT be recovered!")

            except Exception as e:
                print(f"  ❌ Error: {e}")

        # ── Decrypt ───────────────────────────────────────────────────────
        elif choice == "2":
            print("\n  🔓 DECRYPT FILE")
            print("  ─────────────────────────────────────────")
            file_path = input("  File path to decrypt (.encrypted): ").strip().strip('"')

            if not os.path.exists(file_path):
                print(f"  ❌ File not found: {file_path}")
                continue

            password = getpass.getpass("  Enter decryption password: ")
            if not password:
                print("  ❌ Password cannot be empty.")
                continue

            print("\n  ⏳ Decrypting...")

            try:
                output = decrypt_file(file_path, password)
                info   = get_file_info(output)
                print(f"\n  ✅ File decrypted successfully!")
                print(f"  📁 Output file : {output}")
                print(f"  📦 File size   : {info['size']}")

            except ValueError as e:
                print(f"\n  {e}")
            except Exception as e:
                print(f"\n  ❌ Error: {e}")

        # ── File info ─────────────────────────────────────────────────────
        elif choice == "3":
            print("\n  ℹ️  FILE INFO")
            print("  ─────────────────────────────────────────")
            file_path = input("  File path: ").strip().strip('"')

            if not os.path.exists(file_path):
                print(f"  ❌ File not found: {file_path}")
                continue

            try:
                info = get_file_info(file_path)
                print(f"\n  Name      : {info['name']}")
                print(f"  Size      : {info['size']}")
                print(f"  Type      : {info['type']}")
                print(f"  Encrypted : {'✅ Yes' if info['encrypted'] else '❌ No'}")
            except Exception as e:
                print(f"  ❌ Error: {e}")

        # ── Exit ──────────────────────────────────────────────────────────
        elif choice == "4":
            print("\n  Stay secure! 🔐👋\n")
            break

        else:
            print("  ❌ Invalid choice. Please enter 1, 2, 3, or 4.")


if __name__ == "__main__":
    main()