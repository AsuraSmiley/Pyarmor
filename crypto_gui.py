import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    messagebox.showinfo("Success", "RSA key pair generated and saved.")
    return private_key, public_key

def load_rsa_keys():
    try:
        with open("private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(), password=None
            )
        with open("public_key.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        return private_key, public_key
    except FileNotFoundError:
        messagebox.showinfo("Info", "Keys not found. Generating new ones...")
        return generate_rsa_keys()

def encrypt_aes_key(aes_key, public_key):
    return public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_aes_key(encrypted_key, private_key):
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def encrypt_aes(plain_text, aes_key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(plain_text.encode()) + encryptor.finalize()

def decrypt_aes(cipher_text, aes_key):
    iv = cipher_text[:16]
    cipher_text = cipher_text[16:]
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return (decryptor.update(cipher_text) + decryptor.finalize()).decode()

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Crypto App")
        
        self.mode_var = tk.StringVar(value="encrypt")
        
        tk.Label(root, text="Mode:").grid(row=0, column=0, padx=10, pady=10)
        tk.Radiobutton(root, text="Encrypt", variable=self.mode_var, value="encrypt").grid(row=0, column=1, padx=10, pady=10)
        tk.Radiobutton(root, text="Decrypt", variable=self.mode_var, value="decrypt").grid(row=0, column=2, padx=10, pady=10)
        
        tk.Label(root, text="Message:").grid(row=1, column=0, padx=10, pady=10)
        self.message_entry = tk.Entry(root, width=50)
        self.message_entry.grid(row=1, column=1, columnspan=2, padx=10, pady=10)
        tk.Button(root, text="Clear", command=lambda: self.message_entry.delete(0, tk.END)).grid(row=1, column=3, padx=5, pady=10)
        
        tk.Label(root, text="Encrypted AES Key:").grid(row=2, column=0, padx=10, pady=10)
        self.key_entry = tk.Entry(root, width=50)
        self.key_entry.grid(row=2, column=1, columnspan=2, padx=10, pady=10)
        tk.Button(root, text="Clear", command=lambda: self.key_entry.delete(0, tk.END)).grid(row=2, column=3, padx=5, pady=10)
        
        self.process_button = tk.Button(root, text="Process", command=self.process)
        self.process_button.grid(row=3, column=1, padx=10, pady=10)
        
        self.result_label = tk.Label(root, text="Result:")
        self.result_label.grid(row=4, column=0, padx=10, pady=10)
        
        self.result_text = tk.Text(root, height=5, width=50)
        self.result_text.grid(row=4, column=1, columnspan=2, padx=10, pady=10)
        tk.Button(root, text="Clear", command=lambda: self.result_text.delete(1.0, tk.END)).grid(row=4, column=3, padx=5, pady=10)
    
    def process(self):
        mode = self.mode_var.get()
        message = self.message_entry.get()
        key = self.key_entry.get()
        
        private_key, public_key = load_rsa_keys()
        
        if mode == "encrypt":
            if not message:
                messagebox.showerror("Error", "Message is required for encryption.")
                return
            
            aes_key = os.urandom(32)
            encrypted_aes_key = encrypt_aes_key(aes_key, public_key)
            encrypted_text = encrypt_aes(message, aes_key)
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, urlsafe_b64encode(encrypted_aes_key).decode())
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, urlsafe_b64encode(encrypted_text).decode())
        
        elif mode == "decrypt":
            if not message:
                messagebox.showerror("Error", "Encrypted message is required for decryption.")
                return
            if not key:
                messagebox.showerror("Error", "Encrypted AES key is required for decryption.")
                return
            
            decrypted_aes_key = decrypt_aes_key(urlsafe_b64decode(key), private_key)
            decrypted_text = decrypt_aes(urlsafe_b64decode(message), decrypted_aes_key)
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, decrypted_text)

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()