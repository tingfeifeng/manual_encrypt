import tkinter as tk
from tkinter import messagebox, scrolledtext
from generator import Generator, PublicKeyParseException, InvalidMessageException

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Elliptic Curve Key Exchange and Encryption")
        # Alice's and Bob's Generators
        self.g = Generator()

        # Generate keys for Alice and Bob
        self.g.DH_keygen()
        # Public Key Display
        self.public_label = tk.Label(root, text="你的公钥:")
        self.public_label.grid(row=0, column=0, sticky="w", padx=10, pady=5)
        self.public_text = scrolledtext.ScrolledText(root, height=3, width=70)
        self.public_text.insert(tk.END, self.g.get_public_key())
        self.public_text.grid(row=1, column=0, sticky="w", padx=10, pady=5)

        # Buttons to Generate New Keys
        self.new_key_button = tk.Button(root, text="生成新的公钥", command=self.new_pk)
        self.new_key_button.grid(row=2, column=0, sticky="w", padx=10, pady=5)

        # Other Public Key Input
        self.other_pk_label = tk.Label(root, text="对方公钥:")
        self.other_pk_label.grid(row=3, column=0, sticky="w", padx=10, pady=5)
        self.other_pk_input = tk.Entry(root, width=50)
        self.other_pk_input.grid(row=4, column=0, sticky="w", padx=10, pady=5)
        
        # Buttons to do key exchange
        self.new_key_button = tk.Button(root, text="交换密钥", command=self.key_exhange)
        self.new_key_button.grid(row=5, column=0, sticky="w", padx=10, pady=5)

        # Message Input
        self.message_label = tk.Label(root, text="明文:")
        self.message_label.grid(row=0, column=1, sticky="w", padx=10, pady=5)
        self.message_input = tk.Entry(root, width=50)
        self.message_input.grid(row=1, column=1, sticky="w", padx=10, pady=5)

        # Encrypt Button
        self.encrypt_button = tk.Button(root, text="加密", command=self.encrypt_message)
        self.encrypt_button.grid(row=2, column=1, sticky="w", padx=10, pady=5)

        # Encrypted Message Display
        self.encrypted_label = tk.Label(root, text="Encrypted Message:")
        self.encrypted_label.grid(row=3, column=1, sticky="w", padx=10, pady=5)
        self.encrypted_text = scrolledtext.ScrolledText(root, height=3, width=70)
        self.encrypted_text.grid(row=4, column=1, sticky="w", padx=10, pady=5)

        # Ciphertext Input
        self.ciphertext_label = tk.Label(root, text="密文:")
        self.ciphertext_label.grid(row=0, column=2, sticky="w", padx=10, pady=5)
        self.ciphertext_input = tk.Entry(root, width=50)
        self.ciphertext_input.grid(row=1, column=2, sticky="w", padx=10, pady=5)
        
        # Decrypt Button
        self.decrypt_button = tk.Button(root, text="解密", command=self.decrypt_message)
        self.decrypt_button.grid(row=2, column=2, sticky="w", padx=10, pady=5)

        # Decrypted Message Display
        self.decrypted_label = tk.Label(root, text="Decrypted Message:")
        self.decrypted_label.grid(row=3, column=2, sticky="w", padx=10, pady=5)
        self.decrypted_text = scrolledtext.ScrolledText(root, height=3, width=70)
        self.decrypted_text.grid(row=4, column=2, sticky="w", padx=10, pady=5)
        # Allow the window to adjust to widget sizes
        root.update_idletasks()  # Ensures that all widgets are drawn before resizing
        root.geometry("")        # Automatically adjusts to the content
        
    def new_pk(self):
        self.g.DH_keygen()
        self.public_text.delete("1.0", tk.END)
        self.public_text.insert(tk.END, self.g.get_public_key())
        
    def key_exhange(self):
        try:
            self.g.DH_key_exchange(self.other_pk_input.get().strip())
        except PublicKeyParseException as e:
            messagebox.showerror("Error", f"Key Exchange Error: {e}")

    def encrypt_message(self):
        try:
            # Get the input message
            message = self.message_input.get().strip()
            if not message:
                messagebox.showerror("Error", "Please enter a message to encrypt.")
                return

            # Encrypt the message
            encrypted_message = self.g.encrypt_message(message)
            self.encrypted_text.delete("1.0", tk.END)
            self.encrypted_text.insert(tk.END, encrypted_message)
        except Exception as e:
            messagebox.showerror("Error", f"Encryption Error: {e}")

    def decrypt_message(self):
        try:
            # Get the encrypted message
            encrypted_message = self.ciphertext_input.get().strip()
            if not encrypted_message:
                messagebox.showerror("Error", "Please enter an encrypted message to decrypt.")
                return

            # Decrypt the message
            decrypted_message = self.g.decrypt_message(encrypted_message)
            self.decrypted_text.delete("1.0", tk.END)
            self.decrypted_text.insert(tk.END, decrypted_message)
        except InvalidMessageException as e:
            messagebox.showerror("Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Decryption Error: {e}")
            
if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
