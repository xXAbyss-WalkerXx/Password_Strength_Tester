import re

def password_strength(password):
    length_regex = re.compile(r'.{8,}')
    uppercase_regex = re.compile(r'[A-Z]')
    lowercase_regex = re.compile(r'[a-z]')
    digit_regex = re.compile(r'\d')
    special_char_regex = re.compile(r'[!@#$%^&*(),.?":{}|<>]')

    is_strong = (
        length_regex.search(password) and
        uppercase_regex.search(password) and
        lowercase_regex.search(password) and
        digit_regex.search(password) and
        special_char_regex.search(password)
    )
    if is_strong:
        return "Strong"
    else:
        return "Weak"

if __name__ == "__main__":
    test_password = input("Enter a password to test its strength: ")
    strength = password_strength(test_password)
    print(f"Password strength: {strength}")
