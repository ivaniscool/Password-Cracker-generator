import hashlib
import random
import string
import tkinter as tk
from tkinter import ttk
from tkinter import font
from zxcvbn import zxcvbn

password_file_name = "rockyou (1).txt"
memo = {}

def md5_hash(password):
    if password in memo:
        return memo[password]
    else:
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        memo[password] = hashed_password
        return hashed_password

def crack_password(hash_value, password_list):
    for password in password_list:
        if md5_hash(password) == hash_value:
            return password
    return None

def check_password():
    password = password_entry.get()
    hash_value = md5_hash(password)
    password_list = open(password_file_name, "r", encoding='utf-8', errors='ignore').readlines()
    password_list = list(map(str.strip, password_list))
    cracked_password = crack_password(hash_value, password_list)
    if cracked_password:
        result_label.configure(text="Password is: {}".format(cracked_password), style='ResultLabel.Success.TLabel')
    else:
        result_label.configure(text="Password not found. The password entered was {}".format(password), style='ResultLabel.Failure.TLabel')
    hashed_password_label.configure(text="Hashed password: {}".format(hash_value))

def create_strong_password():
    length = 12
    strong_password = generate_strong_password(length)
    password_entry.delete(0, tk.END)
    password_entry.insert(tk.END, strong_password)
    generated_password_label.configure(text="Generated Password: {}".format(strong_password))

def generate_strong_password(length):
    if length in memo:
        return memo[length]
    else:
        strong_password = ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(length))
        memo[length] = strong_password
        return strong_password

def check_password_strength():
    password = password_entry.get()
    result = zxcvbn(password)
    strength_percentage = (result['score'] / 4) * 100
    strength_label.configure(text="Password Strength: {}%".format(int(strength_percentage)))

def quit_application():
    root.destroy()

root = tk.Tk()
root.title("Password Checker")
root.geometry("820x400")
root.configure(background='#ffffff')

font_style = font.Font(family="Helvetica", size=14, weight="bold")

style = ttk.Style()
style.configure('TLabel', foreground='#ffffff', background='#8a2be2', font=('Helvetica', 14, 'bold'))
style.configure('ResultLabel.Success.TLabel', foreground='#008000')
style.configure('ResultLabel.Failure.TLabel', foreground='#ff0000')

title_frame = ttk.Frame(root, borderwidth=2, relief="groove")
title_frame.pack(side='top', fill='x')

title_label = ttk.Label(title_frame, text="Password", style='TLabel')
title_label.pack(side='top', padx=10, pady=10)

content_frame = ttk.Frame(root)
content_frame.pack(fill='both', expand=True)

input_pane = ttk.Frame(content_frame, borderwidth=2, relief="groove")
input_pane.grid(row=0, column=0, padx=10, pady=10, sticky='nsew')

output_pane = ttk.Frame(content_frame, borderwidth=2, relief="groove")
output_pane.grid(row=0, column=1, padx=10, pady=10, sticky='nsew')

function_buttons_frame = ttk.Frame(content_frame)
function_buttons_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky='ew')

password_label = ttk.Label(input_pane, text="Enter Password:", style='TLabel')
password_label.pack(side='top', padx=10, pady=10)

password_entry = ttk.Entry(input_pane, show='*', font=font_style)
password_entry.pack(side='top', padx=10, pady=10)

result_label = ttk.Label(output_pane, text="", style='ResultLabel.Failure.TLabel')
result_label.pack(side='top', padx=10, pady=10)

hashed_password_label = ttk.Label(output_pane, text="", style='TLabel')
hashed_password_label.pack(side='top', padx=10, pady=10)

strength_label = ttk.Label(output_pane, text="", style='TLabel')
strength_label.pack(side='top', padx=10, pady=10)

generated_password_label = ttk.Label(output_pane, text="", style='TLabel')
generated_password_label.pack(side='top', padx=10, pady=10)

check_button = ttk.Button(function_buttons_frame, text="Check Password", style='TLabel', command=check_password)
check_button.pack(side='left', padx=10, pady=10)

strong_password_button = ttk.Button(function_buttons_frame, text="Generate Strong Password", style='TLabel', command=create_strong_password)
strong_password_button.pack(side='left', padx=10, pady=10)

check_strength_button = ttk.Button(function_buttons_frame, text="Check Password Strength", style='TLabel', command=check_password_strength)
check_strength_button.pack(side='left', padx=10, pady=10)

quit_button = ttk.Button(function_buttons_frame, text="Quit", style='TLabel', command=quit_application)
quit_button.pack(side='right', padx=10, pady=10)

content_frame.columnconfigure(0, weight=1)
content_frame.columnconfigure(1, weight=1)
content_frame.rowconfigure(0, weight=1)

root.mainloop()
