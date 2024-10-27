import re
import string
from math import log2

# A small set of common passwords to flag very insecure ones
COMMON_PASSWORDS = {'password', '123456', '123456789', 'qwerty', 'abc123', 'letmein', 'monkey', 'dragon'}

def calculate_entropy(password):
    """
    Calculate the estimated entropy of the password.
    
    Parameters:
    - password (str): The password to calculate entropy for.
    
    Returns:
    - float: The estimated entropy.
    """
    # Character pool size estimation
    pool_size = 0
    if re.search(r"[a-z]", password):
        pool_size += 26  # Lowercase letters
    if re.search(r"[A-Z]", password):
        pool_size += 26  # Uppercase letters
    if re.search(r"[0-9]", password):
        pool_size += 10  # Digits
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?`~]", password):
        pool_size += 32  # Special characters
    
    # If no diversity is found, set a minimal pool size to prevent division by zero
    pool_size = max(pool_size, 1)
    
    # Entropy formula: log2(pool_size^length) = length * log2(pool_size)
    return len(password) * log2(pool_size)

def assess_password_strength(password):
    """
    Assess the strength of a password based on various criteria.
    
    Parameters:
    - password (str): The password to assess.
    
    Returns:
    - str: A message indicating the strength of the password and suggestions.
    """
    length_criteria = len(password) >= 12
    upper_criteria = re.search(r"[A-Z]", password) is not None
    lower_criteria = re.search(r"[a-z]", password) is not None
    digit_criteria = re.search(r"[0-9]", password) is not None
    special_criteria = re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?`~]", password) is not None
    repeated_criteria = len(set(password)) > len(password) * 0.6  # Less than 40% repetition
    
    # Sequential letters or numbers (e.g., "abcd", "1234")
    sequential_criteria = not bool(re.search(r"(012|123|234|345|456|567|678|789|890|abcd|bcde|cdef|defg|efgh|fghi|ghij|ijkl|jklm|klmn|lmno|mnop|nopq|opqr|pqrs|qrst|rstu|stuv|tuvw|uvwx|vwxy|wxyz)", password.lower()))
    
    # Common words check
    dictionary_criteria = password.lower() not in COMMON_PASSWORDS

    # Calculate entropy
    entropy = calculate_entropy(password)

    # Count how many criteria the password meets
    criteria_met = sum([length_criteria, upper_criteria, lower_criteria, digit_criteria, special_criteria, repeated_criteria, sequential_criteria, dictionary_criteria])

    # Determine the strength of the password
    feedback = []
    if criteria_met >= 7 and entropy >= 70:
        feedback.append("\033[92mPassword Strength: Very Strong\033[0m")
        feedback.append("Excellent! Your password is highly secure.")
    elif criteria_met >= 5 and entropy >= 60:
        feedback.append("\033[94mPassword Strength: Strong\033[0m")
        feedback.append("Your password is quite secure. Consider increasing the length for extra strength.")
    elif criteria_met >= 4 and entropy >= 50:
        feedback.append("\033[93mPassword Strength: Medium\033[0m")
        feedback.append("Your password is average. Add more complexity, such as special characters or digits.")
    else:
        feedback.append("\033[91mPassword Strength: Weak\033[0m")
        feedback.append("Your password is weak. Consider the following suggestions:")
        if not length_criteria:
            feedback.append("- Make the password at least 12 characters long.")
        if not upper_criteria:
            feedback.append("- Add some uppercase letters.")
        if not lower_criteria:
            feedback.append("- Add some lowercase letters.")
        if not digit_criteria:
            feedback.append("- Include some digits.")
        if not special_criteria:
            feedback.append("- Use special characters like @, #, $, etc.")
        if not repeated_criteria:
            feedback.append("- Avoid using too many repeated characters.")
        if not sequential_criteria:
            feedback.append("- Avoid using sequences like 'abcd' or '1234'.")
        if not dictionary_criteria:
            feedback.append("- Avoid using common passwords or easy-to-guess words.")
    
    feedback.append(f"Estimated Entropy: {entropy:.2f} bits")
    return "\n".join(feedback)

def main():
    print("Advanced Password Strength Assessment Tool")
    password = input("Enter a password to assess its strength: ")
    result = assess_password_strength(password)
    print(result)

if __name__ == "__main__":
    main()
