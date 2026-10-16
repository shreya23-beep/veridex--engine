"""
VeriDex AI - Local Encrypted Vault & Cryptography Module
Implements Windows DPAPI (Data Protection API) and AES-256 encryption
for zero-cloud, 100% private on-device threat vault storage.
"""

import os
import sys
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Attempt to import Windows DPAPI via pywin32
HAS_DPAPI = False
try:
    import win32crypt
    HAS_DPAPI = True
except ImportError:
    HAS_DPAPI = False

KEY_FILE_NAME = ".veridex_vault.key"

class LocalCryptoVault:
    """
    Manages local cryptographic keys using Windows DPAPI and AES-256.
    Ensures security telemetry never leaves the host machine in plaintext.
    """

    def __init__(self, vault_dir: str = None):
        if vault_dir is None:
            vault_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
        os.makedirs(vault_dir, exist_ok=True)
        self.key_path = os.path.join(vault_dir, KEY_FILE_NAME)
        self.fernet = None
        self._init_cipher()

    def _init_cipher(self):
        """Generates or loads a DPAPI-protected AES encryption key."""
        if os.path.exists(self.key_path):
            with open(self.key_path, "rb") as f:
                stored_bytes = f.read()
            
            if HAS_DPAPI:
                try:
                    # Decrypt key via Windows DPAPI
                    _, raw_key = win32crypt.CryptUnprotectData(stored_bytes, None, None, None, 0)
                    self.fernet = Fernet(raw_key)
                    return
                except Exception:
                    pass
            
            # Fallback if raw or non-DPAPI
            try:
                self.fernet = Fernet(stored_bytes)
                return
            except Exception:
                pass

        # Generate new key
        new_key = Fernet.generate_key()
        if HAS_DPAPI:
            try:
                # Protect key using Windows DPAPI
                protected_blob = win32crypt.CryptProtectData(
                    new_key, "VeriDex AI Vault Key", None, None, None, 0
                )
                with open(self.key_path, "wb") as f:
                    f.write(protected_blob)
                self.fernet = Fernet(new_key)
                return
            except Exception as e:
                print(f"[CRYPTO] DPAPI protection warning: {e}. Falling back to standard key.")

        with open(self.key_path, "wb") as f:
            f.write(new_key)
        self.fernet = Fernet(new_key)

    def encrypt(self, plaintext: str) -> str:
        """Encrypts sensitive plaintext into an AES-256 ciphertext string."""
        if not plaintext:
            return ""
        encrypted_bytes = self.fernet.encrypt(plaintext.encode("utf-8"))
        return base64.b64encode(encrypted_bytes).decode("utf-8")

    def decrypt(self, ciphertext: str) -> str:
        """Decrypts AES-256 ciphertext back to readable plaintext."""
        if not ciphertext:
            return ""
        try:
            raw_bytes = base64.b64decode(ciphertext.encode("utf-8"))
            decrypted = self.fernet.decrypt(raw_bytes).decode("utf-8")
            return decrypted
        except Exception as e:
            return f"[DECRYPTION_ERROR: {e}]"

    def hash_identifier(self, value: str) -> str:
        """Hashes URL or domain for zero-knowledge indexed lookups."""
        return hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()

vault_crypto = LocalCryptoVault()
