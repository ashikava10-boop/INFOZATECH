import os
import base64

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
def caesar_encrypt(text, shift):
    result = ""

    for char in text:
        if char.isascii() and char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char

    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)


def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def aes_encrypt(message, password):
    salt = os.urandom(16)
    key = generate_key(password, salt)
    cipher = Fernet(key)

    encrypted = cipher.encrypt(message.encode())
    return base64.urlsafe_b64encode(salt + encrypted).decode()

def aes_decrypt(encrypted_message, password):
    try:
        data = base64.urlsafe_b64decode(encrypted_message.encode())
        salt = data[:16]
        encrypted = data[16:]

        key = generate_key(password, salt)
        cipher = Fernet(key)

        decrypted = cipher.decrypt(encrypted)
        return decrypted.decode()

    except (InvalidToken, ValueError):
        return "Decryption failed! Check your password or encrypted text."


print("\n===== ENCRYPTION & DECRYPTION TOOLKIT =====")
print("1. Caesar Cipher")
print("2. AES Encryption")
print("3. AES Decryption")

choice = input("Choose an option (1-3): ")

if choice == "1":
    message = input("Enter your message: ")
    shift = int(input("Enter shift value: "))
    encrypted = caesar_encrypt(message, shift)
    print("Encrypted text:", encrypted)
    print("Decrypted text:", caesar_decrypt(encrypted, shift))

elif choice == "2":
    message = input("Enter text to encrypt: ")
    password = input("Create a password: ")
    encrypted = aes_encrypt(message, password)
    print("Encrypted text:", encrypted)

elif choice == "3":
    encrypted = input("Enter encrypted text: ")
    password = input("Enter password: ")
    print("Decrypted text:", aes_decrypt(encrypted, password))

else:
    print("Invalid choice!")
