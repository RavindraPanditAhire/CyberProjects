import tkinter as tk
from tkinter import ttk, messagebox
import hashlib
import base64
import secrets
import string
import re
from cryptography.fernet import Fernet
import requests
import socket
import threading
import nmap

class SecurityToolSuite:
    def __init__(self, root):
        self.root = root
        self.root.title("Security Tool Suite")
        self.root.geometry("800x600")
        self.root.configure(bg='#2c3e50')

        # Create notebook for different tools
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(pady=10, expand=True)

        # Create different tabs for tools
        self.password_frame = ttk.Frame(self.notebook)
        self.encryption_frame = ttk.Frame(self.notebook)
        self.network_frame = ttk.Frame(self.notebook)
        self.hash_frame = ttk.Frame(self.notebook)

        self.notebook.add(self.password_frame, text="Password Tools")
        self.notebook.add(self.encryption_frame, text="Encryption")
        self.notebook.add(self.network_frame, text="Network Tools")
        self.notebook.add(self.hash_frame, text="Hash Generator")

        # Initialize all tools
        self.init_password_tools()
        self.init_encryption_tools()
        self.init_network_tools()
        self.init_hash_tools()

    def init_password_tools(self):
        # Password Generator
        ttk.Label(self.password_frame, text="Password Generator", font=('Helvetica', 12, 'bold')).pack(pady=10)
        
        # Password options frame
        options_frame = ttk.Frame(self.password_frame)
        options_frame.pack(pady=5)

        self.length_var = tk.IntVar(value=12)
        ttk.Label(options_frame, text="Length:").grid(row=0, column=0, padx=5)
        ttk.Entry(options_frame, textvariable=self.length_var, width=5).grid(row=0, column=1)

        self.use_uppercase = tk.BooleanVar(value=True)
        self.use_lowercase = tk.BooleanVar(value=True)
        self.use_numbers = tk.BooleanVar(value=True)
        self.use_symbols = tk.BooleanVar(value=True)

        ttk.Checkbutton(options_frame, text="Uppercase", variable=self.use_uppercase).grid(row=1, column=0)
        ttk.Checkbutton(options_frame, text="Lowercase", variable=self.use_lowercase).grid(row=1, column=1)
        ttk.Checkbutton(options_frame, text="Numbers", variable=self.use_numbers).grid(row=2, column=0)
        ttk.Checkbutton(options_frame, text="Symbols", variable=self.use_symbols).grid(row=2, column=1)

        ttk.Button(self.password_frame, text="Generate Password", command=self.generate_password).pack(pady=5)
        
        self.password_result = tk.Text(self.password_frame, height=2, width=40)
        self.password_result.pack(pady=5)

        # Password Strength Checker
        ttk.Label(self.password_frame, text="\nPassword Strength Checker", font=('Helvetica', 12, 'bold')).pack(pady=10)
        self.check_password_entry = ttk.Entry(self.password_frame, width=40)
        self.check_password_entry.pack(pady=5)
        ttk.Button(self.password_frame, text="Check Strength", command=self.check_password_strength).pack(pady=5)
        self.strength_result = tk.Text(self.password_frame, height=4, width=40)
        self.strength_result.pack(pady=5)

    def init_encryption_tools(self):
        ttk.Label(self.encryption_frame, text="Text Encryption/Decryption", font=('Helvetica', 12, 'bold')).pack(pady=10)
        
        # Key generation
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)
        
        # Input text
        ttk.Label(self.encryption_frame, text="Enter Text:").pack(pady=5)
        self.encrypt_text = tk.Text(self.encryption_frame, height=4, width=40)
        self.encrypt_text.pack(pady=5)
        
        # Buttons
        button_frame = ttk.Frame(self.encryption_frame)
        button_frame.pack(pady=5)
        ttk.Button(button_frame, text="Encrypt", command=self.encrypt_text_data).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Decrypt", command=self.decrypt_text_data).pack(side=tk.LEFT, padx=5)
        
        # Result
        ttk.Label(self.encryption_frame, text="Result:").pack(pady=5)
        self.encryption_result = tk.Text(self.encryption_frame, height=4, width=40)
        self.encryption_result.pack(pady=5)

    def init_network_tools(self):
        ttk.Label(self.network_frame, text="Network Tools", font=('Helvetica', 12, 'bold')).pack(pady=10)
        
        # Port Scanner
        ttk.Label(self.network_frame, text="Port Scanner").pack(pady=5)
        self.host_entry = ttk.Entry(self.network_frame, width=40)
        self.host_entry.insert(0, "localhost")
        self.host_entry.pack(pady=5)
        
        port_frame = ttk.Frame(self.network_frame)
        port_frame.pack(pady=5)
        ttk.Label(port_frame, text="Port Range:").pack(side=tk.LEFT)
        self.start_port = ttk.Entry(port_frame, width=6)
        self.start_port.insert(0, "1")
        self.start_port.pack(side=tk.LEFT, padx=5)
        ttk.Label(port_frame, text="to").pack(side=tk.LEFT)
        self.end_port = ttk.Entry(port_frame, width=6)
        self.end_port.insert(0, "1024")
        self.end_port.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(self.network_frame, text="Scan Ports", command=self.scan_ports).pack(pady=5)
        
        self.port_result = tk.Text(self.network_frame, height=10, width=40)
        self.port_result.pack(pady=5)

    def init_hash_tools(self):
        ttk.Label(self.hash_frame, text="Hash Generator", font=('Helvetica', 12, 'bold')).pack(pady=10)
        
        # Input text
        ttk.Label(self.hash_frame, text="Enter Text:").pack(pady=5)
        self.hash_text = tk.Text(self.hash_frame, height=4, width=40)
        self.hash_text.pack(pady=5)
        
        # Hash type selection
        self.hash_type = tk.StringVar(value="md5")
        hash_frame = ttk.Frame(self.hash_frame)
        hash_frame.pack(pady=5)
        ttk.Radiobutton(hash_frame, text="MD5", variable=self.hash_type, value="md5").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(hash_frame, text="SHA-1", variable=self.hash_type, value="sha1").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(hash_frame, text="SHA-256", variable=self.hash_type, value="sha256").pack(side=tk.LEFT, padx=5)
        
        ttk.Button(self.hash_frame, text="Generate Hash", command=self.generate_hash).pack(pady=5)
        
        self.hash_result = tk.Text(self.hash_frame, height=4, width=40)
        self.hash_result.pack(pady=5)

    def generate_password(self):
        length = self.length_var.get()
        characters = ""
        if self.use_uppercase.get():
            characters += string.ascii_uppercase
        if self.use_lowercase.get():
            characters += string.ascii_lowercase
        if self.use_numbers.get():
            characters += string.digits
        if self.use_symbols.get():
            characters += string.punctuation

        if not characters:
            messagebox.showerror("Error", "Please select at least one character type")
            return

        password = ''.join(secrets.choice(characters) for _ in range(length))
        self.password_result.delete(1.0, tk.END)
        self.password_result.insert(tk.END, password)

    def check_password_strength(self):
        password = self.check_password_entry.get()
        strength = 0
        feedback = []

        if len(password) >= 8:
            strength += 1
            feedback.append("✓ Length is good")
        else:
            feedback.append("✗ Password should be at least 8 characters")

        if re.search(r'[A-Z]', password):
            strength += 1
            feedback.append("✓ Contains uppercase")
        else:
            feedback.append("✗ Should contain uppercase letters")

        if re.search(r'[a-z]', password):
            strength += 1
            feedback.append("✓ Contains lowercase")
        else:
            feedback.append("✗ Should contain lowercase letters")

        if re.search(r'\d', password):
            strength += 1
            feedback.append("✓ Contains numbers")
        else:
            feedback.append("✗ Should contain numbers")

        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            strength += 1
            feedback.append("✓ Contains special characters")
        else:
            feedback.append("✗ Should contain special characters")

        strength_text = {
            0: "Very Weak",
            1: "Weak",
            2: "Fair",
            3: "Good",
            4: "Strong",
            5: "Very Strong"
        }

        self.strength_result.delete(1.0, tk.END)
        self.strength_result.insert(tk.END, f"Strength: {strength_text[strength]}\n")
        for item in feedback:
            self.strength_result.insert(tk.END, f"{item}\n")

    def encrypt_text_data(self):
        text = self.encrypt_text.get(1.0, tk.END).strip()
        if text:
            encrypted_text = self.cipher_suite.encrypt(text.encode())
            self.encryption_result.delete(1.0, tk.END)
            self.encryption_result.insert(tk.END, encrypted_text.decode())

    def decrypt_text_data(self):
        try:
            encrypted_text = self.encryption_result.get(1.0, tk.END).strip()
            if encrypted_text:
                decrypted_text = self.cipher_suite.decrypt(encrypted_text.encode())
                self.encryption_result.delete(1.0, tk.END)
                self.encryption_result.insert(tk.END, decrypted_text.decode())
        except Exception as e:
            messagebox.showerror("Error", "Invalid encrypted text")

    def scan_ports(self):
        host = self.host_entry.get()
        start_port = int(self.start_port.get())
        end_port = int(self.end_port.get())
        
        self.port_result.delete(1.0, tk.END)
        self.port_result.insert(tk.END, f"Scanning {host} for open ports...\n")
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                if result == 0:
                    self.port_result.insert(tk.END, f"Port {port} is open\n")
                sock.close()
            except:
                pass

        threads = []
        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=scan_port, args=(port,))
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

        self.port_result.insert(tk.END, "Scan complete!\n")

    def generate_hash(self):
        text = self.hash_text.get(1.0, tk.END).strip()
        hash_type = self.hash_type.get()
        
        if text:
            if hash_type == "md5":
                hash_object = hashlib.md5(text.encode())
            elif hash_type == "sha1":
                hash_object = hashlib.sha1(text.encode())
            else:
                hash_object = hashlib.sha256(text.encode())
            
            hash_result = hash_object.hexdigest()
            self.hash_result.delete(1.0, tk.END)
            self.hash_result.insert(tk.END, hash_result)

if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityToolSuite(root)
    root.mainloop()
