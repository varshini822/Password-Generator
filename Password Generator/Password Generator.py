import tkinter as tk
from tkinter import ttk
import random
import string

# ----- Strength Checker -----
def get_strength(password):
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in string.punctuation for c in password)

    score = sum([has_upper, has_lower, has_digit, has_symbol])

    if length >= 12 and score == 4:
        return "Strong", "green"
    elif length >= 8 and score >= 3:
        return "Medium", "orange"
    else:
        return "Weak", "red"

# ----- Password Generator -----
def generate_password():
    length = length_var.get()
    include_upper = upper_var.get()
    include_lower = lower_var.get()
    include_digits = digit_var.get()
    include_symbols = symbol_var.get()

    if not any([include_upper, include_lower, include_digits, include_symbols]):
        result_label.config(text="Select at least one character type!", fg="red")
        return

    char_pool = ""
    if include_upper:
        char_pool += string.ascii_uppercase
    if include_lower:
        char_pool += string.ascii_lowercase
    if include_digits:
        char_pool += string.digits
    if include_symbols:
        char_pool += string.punctuation

    password = ''.join(random.choices(char_pool, k=length))
    entry_password.delete(0, tk.END)
    entry_password.insert(0, password)

    strength, color = get_strength(password)
    strength_label.config(text=f"Strength: {strength}", fg=color)
    result_label.config(text="Password Generated!", fg="green")

# ----- Copy to Clipboard -----
def copy_to_clipboard():
    password = entry_password.get()
    if password:
        window.clipboard_clear()
        window.clipboard_append(password)
        result_label.config(text="Copied to Clipboard!", fg="blue")
    else:
        result_label.config(text="Nothing to Copy!", fg="red")

# ----- Show/Hide Password -----
def toggle_visibility():
    if entry_password.cget('show') == "":
        entry_password.config(show="*")
        btn_show.config(text="👁️")
    else:
        entry_password.config(show="")
        btn_show.config(text="🙈")

# ----- Clear All -----
def clear_fields():
    entry_password.delete(0, tk.END)
    length_var.set(12)
    upper_var.set(True)
    lower_var.set(True)
    digit_var.set(True)
    symbol_var.set(True)
    strength_label.config(text="")
    result_label.config(text="")

# ----- GUI Setup -----
window = tk.Tk()
window.title("🔐 Password Generator Pro")
window.geometry("500x520")
window.config(bg="#f0f8ff")

title = tk.Label(window, text="Advanced Password Generator", font=("Helvetica", 18, "bold"), bg="#f0f8ff", fg="#2c3e50")
title.pack(pady=15)

# Frame for Options
frame_options = ttk.LabelFrame(window, text="Options", padding=20)
frame_options.pack(padx=20, pady=10, fill="x")

length_var = tk.IntVar(value=12)
upper_var = tk.BooleanVar(value=True)
lower_var = tk.BooleanVar(value=True)
digit_var = tk.BooleanVar(value=True)
symbol_var = tk.BooleanVar(value=True)

ttk.Label(frame_options, text="Length:").grid(row=0, column=0, sticky="w", pady=5)
ttk.Scale(frame_options, from_=4, to=50, variable=length_var, orient="horizontal", length=200).grid(row=0, column=1, columnspan=2, pady=5)

ttk.Checkbutton(frame_options, text="Include Uppercase (A-Z)", variable=upper_var).grid(row=1, column=0, columnspan=2, sticky="w", pady=5)
ttk.Checkbutton(frame_options, text="Include Lowercase (a-z)", variable=lower_var).grid(row=2, column=0, columnspan=2, sticky="w", pady=5)
ttk.Checkbutton(frame_options, text="Include Digits (0-9)", variable=digit_var).grid(row=3, column=0, columnspan=2, sticky="w", pady=5)
ttk.Checkbutton(frame_options, text="Include Symbols (!@#$)", variable=symbol_var).grid(row=4, column=0, columnspan=2, sticky="w", pady=5)

# Output Frame
frame_output = tk.Frame(window, bg="#f0f8ff")
frame_output.pack(pady=15)

entry_password = ttk.Entry(frame_output, font=("Arial", 14), width=30, show="*")
entry_password.grid(row=0, column=0, padx=10)

btn_show = tk.Button(frame_output, text="👁️", command=toggle_visibility)
btn_show.grid(row=0, column=1)

# Strength Indicator
strength_label = tk.Label(window, text="", font=("Arial", 12, "bold"), bg="#f0f8ff")
strength_label.pack()

# Buttons Frame
frame_buttons = tk.Frame(window, bg="#f0f8ff")
frame_buttons.pack(pady=10)

tk.Button(frame_buttons, text="Generate", font=("Arial", 12), bg="#4caf50", fg="white", width=14, command=generate_password).grid(row=0, column=0, padx=10)
tk.Button(frame_buttons, text="Copy", font=("Arial", 12), bg="#2196f3", fg="white", width=10, command=copy_to_clipboard).grid(row=0, column=1, padx=10)
tk.Button(frame_buttons, text="Clear", font=("Arial", 12), bg="#f44336", fg="white", width=10, command=clear_fields).grid(row=0, column=2, padx=10)

# Result Label
result_label = tk.Label(window, text="", font=("Arial", 12), bg="#f0f8ff")
result_label.pack(pady=10)

# Mainloop
window.mainloop()
