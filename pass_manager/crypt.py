import hashlib
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64


def hash_password(user_password, salt):
    """
    Hashes a user password using PBKDF2 and SHA256.

    Args:
        user_password: The user's password.
        salt: The salt used for hashing.

    Returns:
        The hashed password, which will be used to encrypt|decrypt main key, not stored in db.
    """
    temp_encryption_key = hashlib.pbkdf2_hmac('sha256', user_password.encode('utf-8'),
                                              salt, 390000)

    return temp_encryption_key


def encrypt_main_key(user_password, salt):
    """
    Generates a random 32-byte main key and encrypts it using AES-256 encryption with a
    temporary encryption key to safely store.

    Args:
        user_password: The user's password.
        salt: The salt used for encryption.

    Returns:
       The encrypted main key, which is used to encrypt|decrypt user data.

    """
    main_key = secrets.token_bytes(32)
    main_key = base64.b64encode(main_key).decode('utf-8')
    temp_encryption_key = hash_password(user_password, salt)

    encrypted_main_key = encrypt_aes_256(str(main_key), temp_encryption_key)
    return encrypted_main_key


def decrypt_main_key(user_password, salt, encrypted_main_key):
    """
        Decrypts the main key using temp encryption key.

        Args:
            user_password: The user's password.
            salt: The salt used for encryption.
            encrypted_main_key: The encrypted main key to be decrypted.

        Returns:
            The decrypted main key.
            """

    temp_encryption_key = hash_password(user_password, salt)
    main_key = decrypt_aes_256(encrypted_main_key, temp_encryption_key)
    return base64.b64decode(main_key)


def encrypt_aes_256(data, key):
    """
        Encrypts the user data using AES-256 encryption with main key.

        Args:
            data: The data to be encrypted.
            key: The main key (decrypted).

        Returns:
            The encrypted data to safely store in db.
        """
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    iv = cipher.iv
    ct = base64.b64encode(iv + ct_bytes).decode('utf-8')
    return ct


def decrypt_aes_256(encrypted_data, key):
    """
        Decrypts the given AES-256 encrypted data using main key.

        Args:
            encrypted_data: The encrypted user's data.
            key: The main key (decrypted)

        Returns:
            The decrypted data to read, copy, delete.

        """
    ct = base64.b64decode(encrypted_data)
    iv = ct[:16]
    ct = ct[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')
