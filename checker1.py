import re
import hashlib
import requests
import tkinter as tk

# 1. Check password strength
def check_strength(password):
    length = len(password) >= 8
    upper = re.search(r'[A-Z]', password)
    lower = re.search(r'[a-z]', password)
    digit = re.search(r'\d', password)
    special = re.search(r'[!@#$%^&*(),.?":{}|<>]', password)

    score = sum([length, bool(upper), bool(lower), bool(digit), bool(special)])

    if score <= 2:
        return "Weak"
    elif score == 3 or score == 4:
        return "Medium"
    else:
        return "Strong"

# 2. Check if password has been breached
def check_breach(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    try:
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
        if response.status_code != 200:
            return "⚠️ API Error"
        hashes = (line.split(':') for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return f"⚠️ Breached in {count} times!"
        return "✅ Not found in breaches"
    except Exception as e:
        return f"Error: {e}"

# 3. GUI
def run_checker():
    pwd = entry.get()
    strength = check_strength(pwd)
    breach = check_breach(pwd)
    result_label.config(text=f"Strength: {strength}\nBreach Status: {breach}")

# GUI Layout
root = tk.Tk()
root.title("Password Strength & Breach Checker")
root.geometry("450x220")

tk.Label(root, text="🔐 Enter Your Password:", font=('Arial', 12)).pack(pady=5)
entry = tk.Entry(root, show="*", width=40)
entry.pack()

tk.Button(root, text="Check", command=run_checker).pack(pady=10)
result_label = tk.Label(root, text="", font=('Arial', 11), fg='blue')
result_label.pack()

root.mainloop()
