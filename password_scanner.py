import hashlib
import requests
import getpass


def calculate_strength(password):
    score = 0
    feedback = []

    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Use at least 8 characters.")

    if any(char.islower() for char in password):
        score += 1
    else:
        feedback.append("Add lowercase letters.")

    if any(char.isupper() for char in password):
        score += 1
    else:
        feedback.append("Add uppercase letters.")

    if any(char.isdigit() for char in password):
        score += 1
    else:
        feedback.append("Add numbers.")

    if any(not char.isalnum() for char in password):
        score += 1
    else:
        feedback.append("Add special characters.")

    if score <= 2:
        strength = "Weak"
    elif score <= 4:
        strength = "Medium"
    else:
        strength = "Strong"

    return strength, feedback


def check_breach(password):
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    response = requests.get(url, timeout=10)

    if response.status_code != 200:
        raise RuntimeError("Error checking breach database.")

    hashes = response.text.splitlines()

    for line in hashes:
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return int(count)

    return 0


def main():
    print("Password Security Checker")
    print("-------------------------")

    password = getpass.getpass("Enter password to check: ")

    strength, feedback = calculate_strength(password)

    print(f"\nStrength: {strength}")

    if feedback:
        print("\nSuggestions:")
        for item in feedback:
            print(f"- {item}")

    print("\nChecking breach database...")

    try:
        breach_count = check_breach(password)

        if breach_count > 0:
            print(f"Warning: This password appeared in {breach_count:,} data breaches.")
            print("You should not use this password.")
        else:
            print("Good news: This password was not found in known breaches.")

    except Exception as error:
        print(f"Could not check breach database: {error}")


if __name__ == "__main__":
    main()