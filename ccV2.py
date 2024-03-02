import tkinter as tk
from tkinter import ttk
import tkinter.messagebox as messagebox
import hashlib

def CaesarCipher(sentence, key, mode):
    alphabet = "1234567890qwertyuiop[]asdfghjkl;zxcvbnm,.!@#$%^&*()_+-=-{}:<>|QWERTYUIOPASDFGHJKLZXCVBNM ~`?°"
    result = ''

    for char in sentence:
        if char in alphabet:
            if mode == 'Encrypt':
                index = (alphabet.index(char) + key) % len(alphabet)
            elif mode == 'Decrypt':
                index = (alphabet.index(char) - key) % len(alphabet)
            result += alphabet[index]
        else:
            result += char

    return result

def process_input():
    mode = mode_var.get()
    sentence = sentence_entry.get()
    passphrase = passphrase_entry.get()

    if mode == '':
        messagebox.showerror("Error", "Please select Encrypt or Decrypt.")
        return

    if not passphrase:
        messagebox.showerror("Error", "Passphrase cannot be empty.")
        return

    key = generate_key(passphrase)

    result = CaesarCipher(sentence, key, mode)
    result_label.config(text=result)

def generate_key(passphrase):
    return int(hashlib.sha256(passphrase.encode()).hexdigest(), 16) % 50 + 1

def copy_to_clipboard():
    result = result_label.cget("text")
    root.clipboard_clear()
    root.clipboard_append(result)
    messagebox.showinfo("Success", "Result copied to clipboard.")

root = tk.Tk()
root.title("Caesar Cipher")

screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()

root.geometry(f"{screen_width}x{screen_height}")

mode_var = tk.StringVar()

mode_label = tk.Label(root, text="Select mode: ")
mode_label.pack()

mode_combobox = ttk.Combobox(root, textvariable=mode_var, values=["Encrypt", "Decrypt"], state="readonly")
mode_combobox.pack()

tk.Label(root, text="Enter a sentence:").pack()
sentence_entry = tk.Entry(root)
sentence_entry.pack()

tk.Label(root, text="Enter a passphrase:").pack()
passphrase_entry = tk.Entry(root, show="*")
passphrase_entry.pack()

encrypt_button = tk.Button(root, text="Encrypt/Decrypt", command=process_input)
encrypt_button.pack()

result_label = tk.Label(root, text="")
result_label.pack()

copy_button = tk.Button(root, text="Copy Result", command=copy_to_clipboard)
copy_button.pack()

root.mainloop()

