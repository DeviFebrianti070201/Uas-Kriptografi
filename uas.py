from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

def encrypt_text(text, key):
    key = key.ljust(32)[:32].encode('utf-8')  # Memastikan kunci panjangnya 32 byte
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted_text = cipher.encrypt(pad(text.encode('utf-8'), AES.block_size))
    return iv + encrypted_text

def decrypt_text(encrypted_text, key):
    key = key.ljust(32)[:32].encode('utf-8')  # Memastikan kunci panjangnya 32 byte
    iv = encrypted_text[:AES.block_size]
    encrypted_text = encrypted_text[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_text = unpad(cipher.decrypt(encrypted_text), AES.block_size)
    return decrypted_text.decode('utf-8')

import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox

class TextEditorWithEncryption:
    def __init__(self, root):
        self.root = root
        self.root.title("Text Editor with Encryption")
        self.root.geometry("800x600")

        self.text_area = tk.Text(root, wrap='word')
        self.text_area.pack(expand=True, fill='both')

        self.menu = tk.Menu(root)
        self.root.config(menu=self.menu)

        file_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New", command=self.new_file)
        file_menu.add_command(label="Open", command=self.open_file)
        file_menu.add_command(label="Save", command=self.save_file)
        file_menu.add_command(label="Save As Encrypted", command=self.save_file_encrypted)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=root.quit)

        self.current_file = None

    def new_file(self):
        self.text_area.delete(1.0, tk.END)
        self.current_file = None

    def open_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            key = simpledialog.askstring("Input", "Masukkan kunci enkripsi:", show='*')
            if key:
                try:
                    with open(file_path, 'rb') as f:
                        encrypted_text = f.read()
                    text = decrypt_text(encrypted_text, key)
                    self.text_area.delete(1.0, tk.END)
                    self.text_area.insert(tk.END, text)
                    self.current_file = file_path
                except Exception as e:
                    messagebox.showerror("Error", f"Gagal mendekripsi file: {e}")

    def save_file(self):
        if self.current_file:
            with open(self.current_file, 'w') as f:
                f.write(self.text_area.get(1.0, tk.END))
        else:
            self.save_file_as()

    def save_file_as(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                 filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'w') as f:
                f.write(self.text_area.get(1.0, tk.END))
            self.current_file = file_path

    def save_file_encrypted(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".enc",
                                                    filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")])
        if file_path:
            key = simpledialog.askstring("Input", "Masukkan kunci enkripsi:", show='*')
            if key:
                try:
                    text = self.text_area.get(1.0, tk.END)
                    encrypted_text = encrypt_text(text, key)
                    with open(file_path, 'wb') as f:
                        f.write(encrypted_text)
                    self.current_file = file_path
                except Exception as e:
                    messagebox.showerror("Error", f"Gagal mengenkripsi file: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    editor = TextEditorWithEncryption(root)
    root.mainloop()
