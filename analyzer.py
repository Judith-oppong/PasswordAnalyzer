import math
import re
import csv
from datetime import datetime

# ============================================================
# 1. Load Weak Passwords
# ============================================================
def load_weak_passwords(filepath="weak_passwords.txt"):
    try:
        with open(filepath, "r", encoding="utf-8") as file:
            return [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        return []

weak_passwords = load_weak_passwords()
weak_passwords_set = set(p.lower() for p in weak_passwords)

# ============================================================
# 2. Load Leaked Passwords
# ============================================================
def load_leaked_passwords(filepath="datasets/leaked_passwords.txt"):
    try:
        with open(filepath, "r", encoding="utf-8") as file:
            return [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        return []

leaked_passwords = load_leaked_passwords()
leaked_passwords_set = set(p.lower() for p in leaked_passwords)

# ============================================================
# 3. Log Results to CSV
# ============================================================
def log_result(strength, entropy):
    with open("analysis_log.csv", mode="a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            strength,
            entropy
        ])

# ============================================================
# 4. Entropy Calculation
# ============================================================
def calculate_entropy(password):
    charset_size = 0
    if re.search(r'[a-z]', password): charset_size += 26
    if re.search(r'[A-Z]', password): charset_size += 26
    if re.search(r'\d', password): charset_size += 10
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password): charset_size += 32
    if charset_size == 0:
        return 0
    entropy = len(password) * math.log2(charset_size)
    return round(entropy, 2)

# ============================================================
# 5. Brute-Force Time Estimation
# ============================================================
def estimate_bruteforce_time(entropy_bits):
    """Estimate brute-force cracking time assuming 10B guesses/sec."""
    guesses_per_second = 1e10
    total_guesses = 2 ** entropy_bits
    seconds = total_guesses / guesses_per_second

    if seconds < 1:
        return "Instantly crackable"
    elif seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.2f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.2f} hours"
    elif seconds < 31557600:
        return f"{seconds/86400:.2f} days"
    elif seconds < 31557600 * 100:
        return f"{seconds/31557600:.2f} years"
    else:
        return "Centuries (very strong)"

# ============================================================
# 6. Main Password Analyzer
# ============================================================
def analyze_password(password):
    feedback = []
    strength_points = 0
    password_lower = password.lower()

    # Check for leaked passwords FIRST (critical)
    if password_lower in leaked_passwords_set:
        entropy = calculate_entropy(password)
        return {
            "Password": password,
            "Strength": "Very Weak",
            "Entropy": entropy,
            "Score": 0,
            "Bruteforce_Time": estimate_bruteforce_time(entropy),
            "Feedback": [
                "This password appears in leaked password databases.",
                "Attackers can crack this instantly.",
                "Never reuse passwords found in data breaches."
            ]
        }

    # Check if similar to leaked passwords (e.g., password123)
    for leaked in leaked_passwords_set:
        if leaked and leaked in password_lower:
            feedback.append("Your password is too similar to a leaked password. Attackers can easily guess such variations.")
            break

    # --------------------------------------------------------
    # B. Check against weak passwords list
    # --------------------------------------------------------
    if password_lower in weak_passwords_set:
        return {
            "Password": password,
            "Strength": "Very Weak",
            "Entropy": 0,
            "Score": 0,
            "Bruteforce_Time": "Instantly crackable",
            "Feedback": ["This password is extremely common. Choose something unique."]
        }

    # --------------------------------------------------------
    # C. Rule-Based Checks
    # --------------------------------------------------------
    # Length
    if len(password) < 8:
        feedback.append("Too short — use at least 8 characters.")
    elif len(password) < 12:
        feedback.append("Increase length to at least 12 characters for robustness.")
        strength_points += 1
    else:
        strength_points += 2

    # Character variety
    if not re.search(r'[A-Z]', password):
        feedback.append("Add at least one uppercase letter.")
    else:
        strength_points += 1

    if not re.search(r'[a-z]', password):
        feedback.append("Add at least one lowercase letter.")
    else:
        strength_points += 1

    if not re.search(r'\d', password):
        feedback.append("Include at least one number.")
    else:
        strength_points += 1

    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        feedback.append("Add at least one special character.")
    else:
        strength_points += 1

    # Predictable sequences
    if re.search(r"(123|abc|password|qwerty)", password.lower()):
        feedback.append("Avoid predictable sequences like '123', 'abc', or 'password'.")

    # NEW: Common patterns like Summer2024!
    if re.search(r"(19|20)\d{2}", password):
        feedback.append("Avoid using years (e.g., 2024) — attackers often try these.")

    if re.search(r"[A-Z][a-z]+", password) and re.search(r"\d+", password):
        feedback.append("Pattern detected (Word + Numbers). Consider less predictable formats.")

    # --------------------------------------------------------
    # D. Entropy Evaluation
    # --------------------------------------------------------
    entropy = calculate_entropy(password)
    feedback.append(f"Estimated crack time: {estimate_bruteforce_time(entropy)}")

    if entropy < 40:
        feedback.append("Low entropy — add more character types or increase length.")
    elif entropy < 60:
        strength_points += 1
        feedback.append("Moderate entropy — password can be improved further.")
    else:
        strength_points += 2

    # --------------------------------------------------------
    # E. Final Strength Rating
    # --------------------------------------------------------
    if entropy < 30:
        strength = "Very Weak"
    elif strength_points >= 7:
        strength = "Strong"
    elif strength_points >= 4:
        strength = "Medium"
    else:
        strength = "Weak"

    score = min(100, max(0, int(entropy * 1.2 + strength_points * 5)))

    return {
        "Password": password,
        "Strength": strength,
        "Entropy": entropy,
        "Score": score,
        "Bruteforce_Time": estimate_bruteforce_time(entropy),
        "Feedback": feedback
    }

# ============================================================
# 7. Command-Line Test (Optional)
# ============================================================
if __name__ == "__main__":
    print("Password Analyzer\n")
    pwd = input("Enter a password: ")
    result = analyze_password(pwd)

    print("\nResults:")
    print(f"Strength: {result['Strength']}")
    print(f"Entropy: {result['Entropy']} bits")
    print(f"Bruteforce Time: {result['Bruteforce_Time']}")
    print("Feedback:")
    for tip in result['Feedback']:
        print(f" - {tip}")






