
import string

def check_password(password):
    score = 0
    suggestions = []

    common_passwords = [
        "password",
        "12345678",
        "qwerty",
        "admin"
    ]

    if password.lower() in common_passwords:
        print("Warning: This is a common password!")
        print("Strength: Weak")
        return

    if len(password) >= 8:
        score += 1
    else:
        print("Use at least 8 characters.")

    if any(char.isupper() for char in password):
        score += 1
    else:
        print("Add an uppercase letter.")

    if any(char.islower() for char in password):
        score += 1
    else:
        print("Add a lowercase letter.")

    if any(char.isdigit() for char in password):
        score += 1
    else:
        print("Add a number.")

    if any(char in string.punctuation for char in password):
        score += 1
    else:
        print("Add a symbol.")

    print("\nScore:", score, "/5")

    if score <= 2:
        print("Strength: Weak")
    elif score <= 4:
        print("Strength: Medium")
    else:
        print("Strength: Strong")

    if suggestions:
        print("Suggestions to improve:")
        for suggestion in suggestions:
            print("-", suggestion)
    else:
        print("No improvement suggestions.")

password = input("Enter a password to check: ")
check_password(password)
